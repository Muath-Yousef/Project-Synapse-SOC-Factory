import logging
import json
import os
import sys
from typing import List, Dict, Any

# Define base path to ensure relative imports from root directory work inside testing frameworks
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, BASE_DIR)

from tools.nmap_tool import NmapTool
from parsers.nmap_parser import NmapParser
from tools.nuclei_tool import NucleiTool
from parsers.nuclei_parser import NucleiParser
from tools.dns_tool import DNSTool
from tools.virustotal_tool import VirusTotalTool
from tools.subfinder_tool import SubfinderTool
from parsers.aggregator import Aggregator
from knowledge.vector_store import VectorStore, ClientProfileNotFoundError
from core.llm_manager import LLMManager
from reports.report_generator import ReportGenerator
import yaml

# Phase 7: SOAR Integration
from soc.safety_guard import SafetyGuard
from soc.alert_router import AlertRouter, AlertContext, ActionType
from soc.playbooks.web_attack_playbook import WebAttackPlaybook
from soc.playbooks.hardening_playbook import HardeningPlaybook
from soc.playbooks.malware_playbook import MalwarePlaybook
from soc.playbooks.data_exfil_playbook import DataExfilPlaybook
from soc.playbooks.ransomware_playbook import RansomwarePlaybook
from soc.audit_log import log_action

DRY_RUN = os.getenv("SOAR_DRY_RUN", "true").lower() == "true"

logger = logging.getLogger("Orchestrator")

from soc.delta_analyzer import DeltaAnalyzer
from soc.compliance_engine import ComplianceEngine
import time

class Orchestrator:
    def __init__(self):
        # Initialize the pipeline components
        self.vector_store = VectorStore(persist_dir=os.path.join(BASE_DIR, ".chroma_db_test")) 
        self.nmap_tool = NmapTool()
        self.parser = NmapParser()
        self.nuclei_tool = NucleiTool()
        self.nuclei_parser = NucleiParser()
        self.dns_tool = DNSTool()
        self.vt_tool = VirusTotalTool()
        self.subfinder_tool = SubfinderTool()
        self.aggregator = Aggregator()
        self.llm = LLMManager()
        self.report_gen = ReportGenerator()
        self.delta_analyzer = DeltaAnalyzer()
        self.compliance_engine = ComplianceEngine()
        self.history_dir = os.path.join(BASE_DIR, "knowledge/history")
        os.makedirs(self.history_dir, exist_ok=True)

    def _get_latest_scan(self, client_id: str) -> Dict[str, Any]:
        """Loads the most recent scan JSON for a client."""
        files = [f for f in os.listdir(self.history_dir) if f.startswith(f"{client_id.lower()}_scan_")]
        if not files: return {}
        latest_file = sorted(files)[-1]
        with open(os.path.join(self.history_dir, latest_file), 'r') as f:
            return json.load(f)

    def _persist_scan(self, client_id: str, scan_data: Dict[str, Any]):
        """Saves the current scan JSON for future reference."""
        ts = int(time.time())
        filename = f"{client_id.lower()}_scan_{ts}.json"
        with open(os.path.join(self.history_dir, filename), 'w') as f:
            json.dump(scan_data, f, indent=2)

    def _is_domain(self, target: str) -> bool:
        """Helper to check if target is a domain name."""
        host = target.split(":")[0]
        try:
            import ipaddress
            ipaddress.ip_address(host)
            return False
        except ValueError:
            return True

    def run_triage(self, target_ip: str, client_id: str, **kwargs):
        logger.info(f"--- [PHASE 19 MONITORING STARTED] ---")
        logger.info(f"Target: {target_ip} | Client ID: {client_id}")

        # Step A: Fetch Context
        logger.info("\n[STEP A] Grabbing Context (Memory Retrieval)...")
        try:
            client_profile = self.vector_store.query_context("clients", client_id, n_results=1, client_id=client_id)
            client_context = yaml.dump(client_profile, allow_unicode=True)
            logger.info(f"Context Snippet: {client_context[:100]}...")
        except Exception as e:
            logger.error(f"Retrieval error: {e}")
            client_context = "No Context Found"
            client_profile = {"status": "error"}

        # Step B: Scan & Parse
        logger.info(f"\n[STEP B] Multi-Tool Scanning...")
        raw_xml = self.nmap_tool.run(target_ip, profile="quick")
        self.aggregator.ingest(self.parser.parse(raw_xml))
        
        try:
            raw_nuclei = self.nuclei_tool.run(target_ip)
            self.aggregator.ingest(self.nuclei_parser.parse(raw_nuclei))
        except Exception: pass
            
        try:
            self.aggregator.ingest(self.dns_tool.scan(target_ip))
        except Exception: pass
            
        if self._is_domain(target_ip):
            try:
                self.aggregator.ingest(self.subfinder_tool.run(target_ip))
            except Exception: pass
            
        final_json = self.aggregator.get_final_payload()
        
        # Step C: Analytics (Delta & Scoring)
        logger.info("\n[STEP C] Running Historical Data Analytics...")
        old_scan = self._get_latest_scan(client_id)
        delta_findings = self.delta_analyzer.analyze(old_scan, final_json)
        compliance_results = self.compliance_engine.calculate_score(final_json)
        
        # Step D: LLM Triage
        logger.info("\n[STEP D] AI Triage (Gemini 1.5)...")
        triage_report = self.llm.analyze_scan(final_json, client_context)

        # Step E: Reports (with Analytics)
        logger.info("\n[STEP E] Generating Analytical Security Report...")
        md_content = self.report_gen.generate_markdown_report(
            target_ip=target_ip,
            client_id=client_id,
            client_context=client_context,
            scan_data=final_json,
            triage_verdict=triage_report,
            delta_findings=delta_findings,
            compliance_results=compliance_results
        )
        report_path = self.report_gen.save_report(md_content, f"{client_id.lower()}_report.md")
        
        # Step F: Persistence & SOAR
        self._persist_scan(client_id, final_json)
        logger.info("\n[STEP F] Executing SOAR Responses...")
        try:
            self.execute_soar_response(final_json, client_profile, bypass_safety=kwargs.get("test_mode", False))
        except Exception as e:
            logger.error(f"SOAR failed: {e}")

        return report_path

    def execute_soar_response(self, aggregated_findings: dict, client_profile: Dict[str, Any], bypass_safety: bool = False):
        """
        Processes findings from the Aggregator and routes them through the SOAR.
        """
        client_name = client_profile.get("client_name", "unknown")
        # Handle whitelisted_ips inside security_profile if nested
        security = client_profile.get("security_profile", {})
        whitelist = security.get("whitelisted_ips", [])
        
        guard    = SafetyGuard(client_whitelist=whitelist)
        router   = AlertRouter()
        web_playbook = WebAttackPlaybook()
        hard_playbook = HardeningPlaybook()

        for finding in aggregated_findings.get("findings", []):
            target_ip = finding.get("target_ip")
            severity  = finding.get("severity", "low")
            ftype     = finding.get("finding_type", "unknown")

            # Safety Check
            if bypass_safety:
                logger.info(f"[SOAR] 🧪 TEST MODE ACTIVE: Bypassing SafetyGuard for {target_ip}")
                safe, reason = True, "Bypassed via --test-mode"
            else:
                safe, reason = guard.is_safe_to_block(target_ip)

            if not safe:
                logger.warning(f"[Guard] Block PREVENTED for {target_ip}: {reason}")
                log_action(client_name, "BLOCKED_BY_GUARD", target_ip, 
                           ftype, severity, DRY_RUN, {"reason": reason})
                # Note: We continue if it's protected from blocking, 
                # but we proceed with routing for ADVISORY actions.
                # However, for this simplified Phase 7, we skip whitelisted IPs from ALL SOAR actions for now.
                continue

            # Routing
            alert = AlertContext(
                client_id=client_name,
                target_ip=target_ip,
                finding_type=ftype,
                severity=severity,
                cve_id=finding.get("vuln_id"),
                source_tool=finding.get("source"),
                raw_finding=finding
            )
            actions = router.route(alert)

            # Processing actions
            for action in actions:
                if action == ActionType.BLOCK_IP:
                    result = web_playbook.execute(alert, dry_run=DRY_RUN)
                    log_action(client_name, "BLOCK_IP", target_ip, ftype, severity, DRY_RUN, result)
                
                elif action == ActionType.PATCH_ADVISORY or ftype == "default_ssh":
                    result = hard_playbook.execute(alert, dry_run=DRY_RUN)
                    log_action(client_name, "HARDENING_ADVISORY", target_ip, ftype, severity, DRY_RUN, result)

                elif ftype in ["malware"]:
                    result = MalwarePlaybook().execute(alert, dry_run=DRY_RUN)
                    log_action(client_name, "MALWARE_ESCALATION", target_ip, ftype, severity, DRY_RUN, result)
                
                elif ftype in ["data_exfiltration"]:
                    result = DataExfilPlaybook().execute(alert, dry_run=DRY_RUN)
                    log_action(client_name, "DATA_EXFIL_RESPONSE", target_ip, ftype, severity, DRY_RUN, result)
                
                elif ftype in ["ransomware_precursor"]:
                    result = RansomwarePlaybook().execute(alert, dry_run=DRY_RUN)
                    log_action(client_name, "P0_RANSOMWARE", target_ip, ftype, severity, DRY_RUN, result)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Synapse Orchestrator - Automated MSSP Triage")
    parser.add_argument("--target", required=True, help="Target IP or Hostname to scan")
    parser.add_argument("--client", required=True, help="Client ID for context retrieval")
    parser.add_argument("--test-mode", action="store_true", help="Bypass SafetyGuard for local verification (WARNING: Never use in production)")
    
    args = parser.parse_args()
    
    # Configure root logging for CLI
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    
    orchestrator = Orchestrator()
    try:
        # Pass test_mode to run_triage which passes it down to SOAR
        report_path = orchestrator.run_triage(args.target, args.client, test_mode=args.test_mode)
        print(f"\n✅ Triage Complete. Report saved to: {report_path}")
    except Exception as e:
        print(f"\n❌ Orchestration Failed: {e}")
        sys.exit(1)
