import logging
import json
import os
import sys

# Define base path to ensure relative imports from root directory work inside testing frameworks
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, BASE_DIR)

from tools.nmap_tool import NmapTool
from parsers.nmap_parser import NmapParser
from tools.nuclei_tool import NucleiTool
from parsers.nuclei_parser import NucleiParser
from parsers.nuclei_parser import NucleiParser
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
from soc.audit_log import log_action

DRY_RUN = os.getenv("SOAR_DRY_RUN", "true").lower() == "true"

logger = logging.getLogger("Orchestrator")

class Orchestrator:
    def __init__(self):
        # Initialize the pipeline components
        self.vector_store = VectorStore(persist_dir=os.path.join(BASE_DIR, ".chroma_db_test")) 
        self.nmap_tool = NmapTool()
        self.parser = NmapParser()
        self.nuclei_tool = NucleiTool()
        self.nuclei_parser = NucleiParser()
        self.aggregator = Aggregator()
        self.llm = LLMManager()
        self.report_gen = ReportGenerator()

    def run_triage(self, target_ip: str, client_id: str):
        logger.info(f"--- [PHASE 5 ORCHESTRATION STARTED] ---")
        logger.info(f"Target: {target_ip} | Client ID: {client_id}")

        # Step A: Fetch Context
        logger.info("\n[STEP A] Grabbing Context (Memory Retrieval)...")
        try:
            # Query the 'clients' collection with a strict filter on client_id
            context_results = self.vector_store.query_context("clients", client_id, n_results=1, client_id=client_id)
            if not context_results:
                client_context = "⚠️ No contextual baseline found for this finding — triage may be incomplete"
                logger.warning(f"No results found for query matching client_id: {client_id}")
            else:
                client_context = context_results[0]
                logger.info(f"Context Snippet: {client_context[:100]}...")
        except ClientProfileNotFoundError as e:
            logger.error(f"Onboarding Error: {e}")
            raise e
        except Exception as e:
            logger.error(f"Unexpected retrieval error: {e}")
            client_context = "No Context Found"

        # Step B: Scan & Parse
        logger.info(f"\n[STEP B] Standardizing Data (Nmap Scanner -> Parser -> Aggregator)...")
        raw_xml = self.nmap_tool.run(target_ip, profile="quick")
        parsed_dict = self.parser.parse(raw_xml)
        self.aggregator.ingest(parsed_dict)
        
        logger.info(f"\n[STEP B.2] Nuclei Vulnerability Scan...")
        try:
            raw_nuclei = self.nuclei_tool.run(target_ip)
            parsed_nuclei = self.nuclei_parser.parse(raw_nuclei)
            self.aggregator.ingest(parsed_nuclei)
        except Exception as e:
            logger.error(f"Nuclei scan failed or not available: {e}")
            
        final_json = self.aggregator.get_final_payload()
        logger.info(f"Standardized Payload Generated (Targets: {len(final_json.get('targets', []))})")
        
        # Step C: LLM Triage
        logger.info("\n[STEP C] Passing to LLM for Triage...")
        triage_report = self.llm.analyze_scan(final_json, client_context)

        # Step D: Print basic mock response
        logger.info("\n[STEP D] Final LLM Output Generated.")
        
        # Step E: Generate Reports
        logger.info("\n[STEP E] Generating Unified Client Markdown Report...")
        md_content = self.report_gen.generate_markdown_report(
            target_ip=target_ip,
            client_id=client_id,
            client_context=client_context,
            scan_data=final_json,
            triage_verdict=triage_report
        )
        report_path = self.report_gen.save_report(md_content, f"{client_id.lower()}_report.md")
        
        # Step F: SOAR Execution (Safety First)
        logger.info("\n[STEP F] Executing SOAR Autonomous Response...")
        try:
            client_profile = yaml.safe_load(client_context) if client_context != "No Context Found" else {}
            self.execute_soar_response(final_json, client_profile)
        except Exception as e:
            logger.error(f"SOAR Execution failed: {e}")

        return report_path

    def execute_soar_response(self, aggregated_findings: dict, client_profile: dict):
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
