"""
soc/control_plane.py — Synapse Control Plane (Phase 24)

Middleware layer between raw findings and SOAR execution.
Enforces four properties that the Phase 22 codebase lacked:
  1. Alert deduplication (idempotency)
  2. Incident state machine  (open → investigating → contained → closed)
  3. Detection feedback loop (FP flags reduce rule weight, suppress noise)
  4. GRC ↔ SOC cross-link   (control failure ↔ detection sensitivity)
"""

import hashlib
import json
import logging
import sqlite3
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Database path ──────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH  = BASE_DIR / "soc" / "control_plane.db"

# ── State machine definition ───────────────────────────────────────────────────
VALID_TRANSITIONS: Dict[str, List[str]] = {
    "open"          : ["investigating", "false_positive"],
    "investigating" : ["contained", "false_positive"],
    "contained"     : ["closed"],
    "false_positive": [],
    "closed"        : [],
}

# ── Weight thresholds ──────────────────────────────────────────────────────────
SUPPRESS_BELOW = 0.1   # rule effectively muted
WARN_BELOW     = 0.4   # analyst notified
FP_DELTA       = -0.10 # per false-positive flag
TP_DELTA       = +0.05 # per true-positive confirmation
MAX_WEIGHT     = 2.0


class ControlPlane:
    """
    Single entry point for alert ingestion, incident tracking,
    FP feedback, and GRC bi-directional linkage.

    Usage:
        cp = ControlPlane()
        alert_id = cp.ingest_alert(
            client_id="TechCo", asset_ip="93.184.216.34",
            finding_type="cleartext_http", severity="high",
            source="nmap", raw_finding={...}
        )
    """

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._init_db()
        self._seed_default_rules()

    # ═══════════════════════════════════════════════════════════════════════════
    # PUBLIC API
    # ═══════════════════════════════════════════════════════════════════════════

    def ingest_alert(
        self,
        client_id: str,
        asset_ip: str,
        finding_type: str,
        severity: str,
        source: str,
        raw_finding: Dict[str, Any],
    ) -> str:
        """
        Entry point for ALL alerts (scanner output OR Wazuh webhook).

        Returns alert_id. If the alert is a duplicate for today, returns
        the existing ID and takes no further action (idempotency).
        """
        asset_id  = self._ensure_asset(client_id, asset_ip)
        alert_id  = self._make_alert_id(client_id, asset_id, finding_type, severity)

        if self._alert_exists(alert_id):
            logger.info(f"[CP] Duplicate suppressed: {alert_id[:10]}… ({finding_type}:{severity})")
            return alert_id

        now = self._now()
        with self._conn() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO alerts
                   (id, client_id, asset_id, finding_type, severity, source,
                    raw_finding, status, fp_score, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (alert_id, client_id, asset_id, finding_type, severity, source,
                 json.dumps(raw_finding), "open", 0.0, now, now),
            )

        # Check rule weight — suppress without action if muted
        rule = self._get_rule(finding_type, severity)
        if rule and rule["weight"] < SUPPRESS_BELOW:
            self._update_alert_status(alert_id, "suppressed")
            logger.info(f"[CP] Alert suppressed by rule weight ({rule['weight']:.2f}): {finding_type}:{severity}")
            return alert_id

        # Route → open Incident
        incident_id = self._open_or_update_incident(
            client_id, asset_id, alert_id, finding_type, severity
        )
        self._update_alert_status(alert_id, "routed", incident_id)

        return alert_id

    def update_incident_state(
        self, incident_id: str, new_state: str,
        actor: str = "auto", note: str = ""
    ) -> None:
        """
        Advance the incident state machine.
        Raises ValueError on invalid transition.
        Propagates FP feedback to detection rules automatically.
        """
        current = self._get_incident_field(incident_id, "state")
        if current is None:
            raise ValueError(f"Incident not found: {incident_id}")

        allowed = VALID_TRANSITIONS.get(current, [])
        if new_state not in allowed:
            raise ValueError(
                f"Invalid transition: {current} → {new_state}. "
                f"Allowed: {allowed}"
            )

        with self._conn() as conn:
            conn.execute(
                "UPDATE incidents SET state=?, updated_at=? WHERE id=?",
                (new_state, self._now(), incident_id),
            )
            if new_state == "closed":
                conn.execute(
                    "UPDATE incidents SET closed_at=? WHERE id=?",
                    (self._now(), incident_id),
                )

        self._append_timeline(incident_id, actor, f"State: {current} → {new_state}. {note}")

        if new_state == "false_positive":
            self._propagate_fp_feedback(incident_id)

    def flag_false_positive(self, alert_id: str, analyst: str = "auto") -> None:
        """Mark alert as FP, close its incident, tune the detection rule."""
        alert = self._get_alert(alert_id)
        if not alert:
            raise ValueError(f"Alert not found: {alert_id}")

        incident_id = alert["incident_id"]
        tuned_by_incident = False
        if incident_id:
            try:
                self.update_incident_state(incident_id, "false_positive", analyst, "Analyst flagged FP")
                tuned_by_incident = True
            except ValueError:
                pass  # already in terminal state

        self._update_alert_status(alert_id, "false_positive")
        # Only tune explicitly if it wasn't handled by the incident state transition
        if not tuned_by_incident:
            self._adjust_rule_weight(alert["finding_type"], alert["severity"], direction="down")

    def flag_true_positive(self, alert_id: str, analyst: str = "auto") -> None:
        """Confirm alert is real — boosts rule weight slightly."""
        alert = self._get_alert(alert_id)
        if not alert:
            raise ValueError(f"Alert not found: {alert_id}")
        self._adjust_rule_weight(alert["finding_type"], alert["severity"], direction="up")
        logger.info(f"[CP] TP confirmed by {analyst}: {alert['finding_type']}:{alert['severity']}")

    # ── GRC ↔ SOC ───────────────────────────────────────────────────────────────

    def grc_control_failed(
        self, client_id: str, control_id: str,
        control_name: str, linked_finding_type: str
    ) -> None:
        """
        Called by ComplianceEngine when a control repeatedly fails.
        Elevates detection sensitivity for the linked finding type.
        """
        self._adjust_rule_weight(linked_finding_type, "high", direction="up")
        self._write_grc_event(
            client_id, None, control_id,
            f"GRC→SOC: '{control_name}' failure → elevated detection for {linked_finding_type}",
            "high"
        )
        logger.info(f"[CP] GRC→SOC: {control_name} failure → rule sensitivity raised for {linked_finding_type}")

    # ── Dashboard metrics ────────────────────────────────────────────────────────

    def get_client_dashboard(self, client_id: str) -> Dict[str, Any]:
        """Real-time SOC state for a client. Used by dashboard.py."""
        with self._conn() as conn:
            open_incidents = conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE client_id=? AND state='open'",
                (client_id,)
            ).fetchone()[0]

            assets_at_risk = conn.execute(
                "SELECT COUNT(*) FROM assets WHERE client_id=? AND risk_score >= 7.0",
                (client_id,)
            ).fetchone()[0]

            top_row = conn.execute(
                """SELECT finding_type, COUNT(*) as cnt FROM alerts
                   WHERE client_id=? GROUP BY finding_type ORDER BY cnt DESC LIMIT 1""",
                (client_id,)
            ).fetchone()

            fp_count = conn.execute(
                """SELECT COUNT(*) FROM alerts
                   WHERE client_id=? AND status='false_positive'
                   AND created_at >= date('now', '-7 days')""",
                (client_id,)
            ).fetchone()[0]

            total_7d = conn.execute(
                """SELECT COUNT(*) FROM alerts
                   WHERE client_id=? AND created_at >= date('now', '-7 days')""",
                (client_id,)
            ).fetchone()[0]

            closed = conn.execute(
                """SELECT created_at, closed_at FROM incidents
                   WHERE client_id=? AND state='closed' AND closed_at IS NOT NULL
                   ORDER BY closed_at DESC LIMIT 20""",
                (client_id,)
            ).fetchall()

        fp_rate = round(fp_count / total_7d * 100, 1) if total_7d else 0.0
        mttr = self._compute_mttr(closed)

        return {
            "open_incidents"  : open_incidents,
            "assets_at_risk"  : assets_at_risk,
            "top_finding_type": top_row[0] if top_row else "none",
            "fp_rate_7d_pct"  : fp_rate,
            "mttr_hours"      : mttr,
            "total_alerts_7d" : total_7d,
        }

    def get_open_incidents(self, client_id: str) -> List[Dict[str, Any]]:
        """Returns all open incidents for a client — used by incident_manager.py."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT id, title, severity, state, asset_id, created_at
                   FROM incidents WHERE client_id=? AND state NOT IN ('closed', 'false_positive')
                   ORDER BY created_at DESC""",
                (client_id,)
            ).fetchall()
        return [dict(zip(["id","title","severity","state","asset_id","created_at"], r)) for r in rows]

    def get_rule_health(self) -> List[Dict[str, Any]]:
        """Returns all detection rules with their weight and FP/TP counts."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, finding_type, severity, weight, fp_count, tp_count, last_tuned FROM detection_rules ORDER BY weight ASC"
            ).fetchall()
        return [dict(zip(["id","finding_type","severity","weight","fp_count","tp_count","last_tuned"], r)) for r in rows]

    # ═══════════════════════════════════════════════════════════════════════════
    # PRIVATE HELPERS
    # ═══════════════════════════════════════════════════════════════════════════

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _make_alert_id(self, client_id, asset_id, finding_type, severity) -> str:
        key = f"{client_id}:{asset_id}:{finding_type}:{severity}:{date.today()}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _alert_exists(self, alert_id: str) -> bool:
        with self._conn() as conn:
            row = conn.execute("SELECT id FROM alerts WHERE id=?", (alert_id,)).fetchone()
        return row is not None

    def _get_alert(self, alert_id: str) -> Optional[Dict]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        return dict(row) if row else None

    def _update_alert_status(self, alert_id: str, status: str, incident_id: str = None) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE alerts SET status=?, incident_id=?, updated_at=? WHERE id=?",
                (status, incident_id, self._now(), alert_id)
            )

    def _ensure_asset(self, client_id: str, ip: str) -> str:
        asset_id = f"{client_id}::{ip}"
        now = self._now()
        with self._conn() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO assets (id, client_id, ip, risk_score, last_seen, created_at)
                   VALUES (?,?,?,0.0,?,?)""",
                (asset_id, client_id, ip, now, now)
            )
            conn.execute(
                "UPDATE assets SET last_seen=? WHERE id=?", (now, asset_id)
            )
        return asset_id

    def _open_or_update_incident(
        self, client_id, asset_id, alert_id, finding_type, severity
    ) -> str:
        # Check for an existing open incident for this asset+finding_type
        with self._conn() as conn:
            row = conn.execute(
                """SELECT id FROM incidents
                   WHERE client_id=? AND asset_id=? AND finding_type_tag=?
                   AND state NOT IN ('closed','false_positive')
                   ORDER BY created_at DESC LIMIT 1""",
                (client_id, asset_id, finding_type)
            ).fetchone()

        if row:
            incident_id = row["id"]
            self._append_timeline(incident_id, "auto", f"Additional alert linked: {alert_id}")
        else:
            incident_id = self._create_incident(client_id, asset_id, finding_type, severity)
            # GRC cross-link for high/critical
            if severity in ("critical", "high"):
                self._write_grc_event(
                    client_id, incident_id, None,
                    f"Incident {incident_id} opened — {finding_type} ({severity})",
                    severity
                )

        return incident_id

    def _create_incident(self, client_id, asset_id, finding_type, severity) -> str:
        # Generate sequential ID: INC-YYYYMMDD-NNNN
        today = date.today().strftime("%Y%m%d")
        with self._conn() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE id LIKE ?",
                (f"INC-{today}-%",)
            ).fetchone()[0]
        incident_id = f"INC-{today}-{count+1:04d}"
        title = f"[{severity.upper()}] {finding_type.replace('_', ' ').title()} on {asset_id.split('::')[-1]}"
        now = self._now()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO incidents
                   (id, client_id, asset_id, title, severity, state,
                    finding_type_tag, playbooks_run, actions_taken, timeline,
                    created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (incident_id, client_id, asset_id, title, severity, "open",
                 finding_type, "[]", "[]",
                 json.dumps([{"ts": now, "actor": "auto", "event": "Incident opened"}]),
                 now, now)
            )
        logger.info(f"[CP] Incident opened: {incident_id} — {title}")
        return incident_id

    def _get_incident_field(self, incident_id: str, field: str):
        with self._conn() as conn:
            row = conn.execute(f"SELECT {field} FROM incidents WHERE id=?", (incident_id,)).fetchone()
        return row[0] if row else None

    def _append_timeline(self, incident_id: str, actor: str, event: str) -> None:
        raw = self._get_incident_field(incident_id, "timeline") or "[]"
        timeline = json.loads(raw)
        timeline.append({"ts": self._now(), "actor": actor, "event": event})
        with self._conn() as conn:
            conn.execute(
                "UPDATE incidents SET timeline=?, updated_at=? WHERE id=?",
                (json.dumps(timeline), self._now(), incident_id)
            )

    def _propagate_fp_feedback(self, incident_id: str) -> None:
        """When an incident closes as FP, tune every linked alert's rule."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT finding_type, severity FROM alerts WHERE incident_id=?",
                (incident_id,)
            ).fetchall()
        for row in rows:
            self._adjust_rule_weight(row["finding_type"], row["severity"], "down")

    def _get_rule(self, finding_type: str, severity: str) -> Optional[Dict]:
        rule_id = f"{finding_type}:{severity}"
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM detection_rules WHERE id=?", (rule_id,)
            ).fetchone()
        return dict(row) if row else None

    def _adjust_rule_weight(self, finding_type: str, severity: str, direction: str) -> None:
        rule_id = f"{finding_type}:{severity}"
        rule = self._get_rule(finding_type, severity)
        if not rule:
            # Auto-create rule at default weight
            with self._conn() as conn:
                conn.execute(
                    """INSERT OR IGNORE INTO detection_rules
                       (id, finding_type, severity, weight, fp_count, tp_count, last_tuned)
                       VALUES (?,?,?,1.0,0,0,?)""",
                    (rule_id, finding_type, severity, self._now())
                )
            rule = {"weight": 1.0, "fp_count": 0, "tp_count": 0}

        delta = FP_DELTA if direction == "down" else TP_DELTA
        new_weight = round(max(0.0, min(MAX_WEIGHT, rule["weight"] + delta)), 3)

        fp_inc = 1 if direction == "down" else 0
        tp_inc = 1 if direction == "up"   else 0

        with self._conn() as conn:
            conn.execute(
                """UPDATE detection_rules
                   SET weight=?, fp_count=fp_count+?, tp_count=tp_count+?, last_tuned=?
                   WHERE id=?""",
                (new_weight, fp_inc, tp_inc, self._now(), rule_id)
            )

        logger.info(f"[CP] Rule weight {rule_id}: {rule['weight']:.3f} → {new_weight:.3f} ({direction})")

        if direction == "down" and new_weight < WARN_BELOW:
            logger.warning(
                f"[CP] ⚠️  Rule {rule_id} weight below {WARN_BELOW} ({new_weight:.3f}) — "
                f"high FP rate. Review recommended."
            )

    def _write_grc_event(
        self, client_id, incident_id, control_id, event, severity
    ) -> None:
        event_id = hashlib.sha256(f"{client_id}{incident_id}{event}{self._now()}".encode()).hexdigest()[:12]
        with self._conn() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO grc_risk_events
                   (id, client_id, incident_id, control_id, event, severity, created_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (event_id, client_id, incident_id, control_id, event, severity, self._now())
            )

    def _compute_mttr(self, closed_rows) -> float:
        """Mean time to resolve in hours."""
        if not closed_rows:
            return 0.0
        durations = []
        for row in closed_rows:
            try:
                opened = datetime.fromisoformat(row[0])
                closed = datetime.fromisoformat(row[1])
                durations.append((closed - opened).total_seconds() / 3600)
            except Exception:
                pass
        return round(sum(durations) / len(durations), 1) if durations else 0.0

    # ═══════════════════════════════════════════════════════════════════════════
    # DATABASE SCHEMA
    # ═══════════════════════════════════════════════════════════════════════════

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS assets (
                    id          TEXT PRIMARY KEY,
                    client_id   TEXT NOT NULL,
                    ip          TEXT,
                    hostname    TEXT,
                    asset_type  TEXT DEFAULT 'server',
                    risk_score  REAL DEFAULT 0.0,
                    last_seen   TEXT,
                    tags        TEXT DEFAULT '[]',
                    created_at  TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id              TEXT PRIMARY KEY,
                    client_id       TEXT NOT NULL,
                    asset_id        TEXT NOT NULL,
                    finding_type    TEXT NOT NULL,
                    severity        TEXT NOT NULL,
                    source          TEXT NOT NULL,
                    raw_finding     TEXT NOT NULL,
                    status          TEXT DEFAULT 'open',
                    incident_id     TEXT,
                    fp_score        REAL DEFAULT 0.0,
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT NOT NULL,
                    FOREIGN KEY (asset_id) REFERENCES assets(id)
                );

                CREATE TABLE IF NOT EXISTS incidents (
                    id              TEXT PRIMARY KEY,
                    client_id       TEXT NOT NULL,
                    asset_id        TEXT NOT NULL,
                    title           TEXT NOT NULL,
                    severity        TEXT NOT NULL,
                    state           TEXT DEFAULT 'open',
                    finding_type_tag TEXT,
                    assigned_to     TEXT DEFAULT 'auto',
                    playbooks_run   TEXT DEFAULT '[]',
                    actions_taken   TEXT DEFAULT '[]',
                    timeline        TEXT DEFAULT '[]',
                    grc_control_id  TEXT,
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT NOT NULL,
                    closed_at       TEXT,
                    FOREIGN KEY (asset_id) REFERENCES assets(id)
                );

                CREATE TABLE IF NOT EXISTS detection_rules (
                    id           TEXT PRIMARY KEY,
                    finding_type TEXT NOT NULL,
                    severity     TEXT NOT NULL,
                    weight       REAL DEFAULT 1.0,
                    fp_count     INTEGER DEFAULT 0,
                    tp_count     INTEGER DEFAULT 0,
                    last_tuned   TEXT,
                    notes        TEXT
                );

                CREATE TABLE IF NOT EXISTS grc_risk_events (
                    id          TEXT PRIMARY KEY,
                    client_id   TEXT NOT NULL,
                    incident_id TEXT,
                    control_id  TEXT,
                    event       TEXT NOT NULL,
                    severity    TEXT,
                    created_at  TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_client    ON alerts(client_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_incidents_client ON incidents(client_id, state);
                CREATE INDEX IF NOT EXISTS idx_assets_client    ON assets(client_id);
            """)
        logger.info(f"[CP] Database ready: {self.db_path}")

    def _seed_default_rules(self) -> None:
        """Seeds the routing table as detection rules at weight=1.0 on first run."""
        default_rules = [
            ("cleartext_http",    "critical"),
            ("cleartext_http",    "high"),
            ("cleartext_http",    "medium"),
            ("cve",               "critical"),
            ("cve",               "high"),
            ("default_ssh",       "high"),
            ("default_ssh",       "medium"),
            ("dns_dmarc",         "high"),
            ("dns_dmarc",         "medium"),
            ("dns_dmarc",         "low"),
            ("dns_spf",           "high"),
            ("dns_spf",           "medium"),
            ("dns_spf",           "low"),
            ("dns_missing_dkim",  "high"),
            ("dns_missing_dkim",  "medium"),
            ("dns_missing_dkim",  "low"),
            ("dns_spf_missing",   "high"),
            ("dns_dmarc_missing", "high"),
            ("dns_dkim_not_found","medium"),
            ("dns_bimi_missing",  "info"),
            ("ip_reputation",     "high"),
            ("ip_reputation",     "medium"),
            ("malware",           "critical"),
            ("malware",           "high"),
            ("data_exfiltration", "critical"),
            ("data_exfiltration", "high"),
            ("ransomware_precursor","critical"),
            ("ransomware_precursor","high"),
        ]
        now = self._now()
        with self._conn() as conn:
            for ft, sev in default_rules:
                conn.execute(
                    """INSERT OR IGNORE INTO detection_rules
                       (id, finding_type, severity, weight, fp_count, tp_count, last_tuned)
                       VALUES (?,?,?,1.0,0,0,?)""",
                    (f"{ft}:{sev}", ft, sev, now)
                )
