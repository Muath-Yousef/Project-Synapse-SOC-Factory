import logging
import os
import json
import time
from datetime import datetime
from typing import Dict, Any
from dotenv import load_dotenv
from core.rate_limiter import RateLimiter

load_dotenv()
_limiter = RateLimiter(calls_per_minute=int(os.getenv("GEMINI_RPM_LIMIT", "15")))

try:
    from google import genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False

logger = logging.getLogger(__name__)


class LLMManager:
    """
    Manages interactions with LLM APIs (Gemini).
    Model priority per SYNAPSE_MASTER_ROADMAP Phase 29.3:
      Primary:   gemini-2.0-flash (stable, free tier)
      Fallback1: gemini-1.5-flash
      Fallback2: Structured offline analysis (clearly labeled)
    """

    MODELS = ["gemini-2.0-flash", "gemini-2.0-flash-lite"]

    def __init__(self, provider="gemini"):
        self.provider = provider
        load_dotenv()
        self.api_key = os.getenv("GEMINI_API_KEY")
        self.last_health = None  # for dashboard health check

        if self.api_key and self.api_key != "your_gemini_key_here" and GENAI_AVAILABLE:
            self.client = genai.Client(api_key=self.api_key)
            self.live_mode = True
        else:
            self.live_mode = False

    # ------------------------------------------------------------------
    # Health check (Phase 29.3 — exposed to dashboard.py)
    # ------------------------------------------------------------------
    def health_check(self) -> Dict[str, Any]:
        """Quick non-destructive API health check."""
        result = {"timestamp": datetime.now().isoformat(), "live_mode": self.live_mode}
        if not self.live_mode:
            result["status"] = "offline"
            result["reason"] = "No API key or google-genai not installed"
            self.last_health = result
            return result

        for model in self.MODELS:
            try:
                resp = self.client.models.generate_content(
                    model=model, contents="Reply with exactly: OK"
                )
                result["status"] = "online"
                result["model"] = model
                result["response"] = resp.text.strip()[:20]
                self.last_health = result
                return result
            except Exception as e:
                err_str = str(e)
                if "429" in err_str or "503" in err_str:
                    continue
                result["status"] = "error"
                result["error"] = err_str[:120]
                self.last_health = result
                return result

        result["status"] = "rate_limited"
        result["reason"] = "All models returned 429/503"
        self.last_health = result
        return result

    # ------------------------------------------------------------------
    # Main analysis
    # ------------------------------------------------------------------
    @_limiter
    def analyze_scan(self, scan_json: Dict[str, Any], client_context: str) -> str:
        """
        Takes standardized JSON and RAG Context to produce an intelligent Triage Report.
        Never returns empty — always returns structured output.
        """
        logger.info(f"[LLMManager] Analyzing scan... (Live Mode: {self.live_mode})")

        if self.live_mode:
            prompt = self._build_prompt(scan_json, client_context)
            for model_name in self.MODELS:
                logger.info(f"[LLMManager] Trying model: {model_name}")
                for attempt in range(3):
                    try:
                        response = self.client.models.generate_content(
                            model=model_name, contents=prompt,
                        )
                        logger.info(f"[LLMManager] Success with {model_name} on attempt {attempt+1}")
                        return response.text
                    except Exception as e:
                        err = str(e)
                        logger.error(f"[LLMManager] {model_name} attempt {attempt+1}/3: {err[:100]}")
                        if "429" in err or "503" in err:
                            wait = 15 * (attempt + 1)  # 15s, 30s, 45s
                            logger.info(f"[LLMManager] Rate limited — waiting {wait}s")
                            time.sleep(wait)
                        else:
                            break  # non-rate error, try next model
            logger.error("[LLMManager] All models/retries exhausted. Using Offline Analysis.")

        # ── Structured Offline Analysis (never empty, clearly labeled) ──
        return self._offline_analysis(scan_json, client_context)

    # ------------------------------------------------------------------
    # Prompt builder
    # ------------------------------------------------------------------
    def _build_prompt(self, scan_json: Dict[str, Any], client_context: str) -> str:
        return f"""You are a hostile security reviewer, not a compliance checker.
Your job is to assume a threat actor perspective.

Rules:
1. An open port is NOT automatically safe because it's "expected".
   Expected ≠ Hardened.
2. For each service found, you MUST evaluate:
   - Is the version exposed? (Version disclosure risk)
   - Is the protocol unencrypted? (Port 80 = cleartext HTTP = data interception risk)
   - Is the port on its default number? (Port 22 default = higher exposure to automated attacks)
3. Compliance context (NCA, ISO 27001) should be used to GENERATE findings,
   not to DISMISS them.
4. Output format: findings ONLY. No "everything is fine" verdicts.
   If there are no critical findings, explicitly state LOW risk with justification.
5. HTTP Redirect Context: Port 80 open does NOT automatically mean cleartext_http risk
   if the target is behind a CDN (Cloudflare, Akamai, Fastly, CloudFront).
   CDN providers use port 80 exclusively for HTTP→HTTPS redirect (301/302).
   Check: if target resolves to a known CDN IP range, downgrade port 80 from
   Critical to Low with note: 'CDN redirect pattern - verify HTTPS enforcement'.
6. Subdomain Attack Surface: If subdomains were discovered, list the top 5
   most interesting ones (admin., api., dev., staging., vpn.) as Medium findings
   requiring investigation.

Client Context (RAG Data):
{client_context}

Scan Results (JSON Format):
{json.dumps(scan_json, indent=2)}"""

    # ------------------------------------------------------------------
    # Offline analysis (structured, never empty, clearly labeled)
    # ------------------------------------------------------------------
    def _offline_analysis(self, scan_json: Dict[str, Any], client_context: str) -> str:
        """Deterministic analysis when API is unavailable. Clearly labeled."""
        targets = scan_json.get("targets", [])
        findings = scan_json.get("findings", [])
        ip = targets[0].get("ip", "Unknown") if targets else "Unknown"
        ports = targets[0].get("open_ports", []) if targets else []

        sections = ["[OFFLINE ANALYSIS — AI API unavailable at time of scan]\n"]

        # Classify findings by severity
        critical = [f for f in findings if f.get("severity", "").lower() == "critical"]
        high = [f for f in findings if f.get("severity", "").lower() == "high"]
        medium = [f for f in findings if f.get("severity", "").lower() == "medium"]

        if critical:
            sections.append("CRITICAL FINDINGS:")
            for f in critical:
                ft = f.get("finding_type", "unknown").replace("_", " ").title()
                sections.append(f"  - {ft}: Requires immediate remediation. "
                                f"Target: {f.get('target_ip', ip)}")

        if high:
            sections.append("\nHIGH FINDINGS:")
            for f in high:
                ft = f.get("finding_type", "unknown").replace("_", " ").title()
                sections.append(f"  - {ft}: Should be addressed within 7 days. "
                                f"Target: {f.get('target_ip', ip)}")

        if medium:
            sections.append("\nMEDIUM FINDINGS:")
            for f in medium:
                ft = f.get("finding_type", "unknown").replace("_", " ").title()
                sections.append(f"  - {ft}: Recommended for next maintenance window.")

        if not findings:
            sections.append("No findings detected in this scan cycle.")

        sections.append(f"\nTotal open ports: {len(ports)}")
        sections.append(f"Total findings: {len(findings)} "
                        f"(Critical: {len(critical)}, High: {len(high)}, Medium: {len(medium)})")
        sections.append("\nNote: This analysis was generated offline. "
                        "A full AI-powered triage will be performed when API quota is restored.")

        return "\n".join(sections)
