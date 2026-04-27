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
from reports.client_report_generator import ClientReportGenerator
from soc.connectors.email_connector import EmailConnector
import yaml

# Phase 24: Orchestrator routes via ControlPlane inline
from soc.audit_log import log_action

DRY_RUN = os.getenv("SOAR_DRY_RUN", "true").lower() == "true"

logger = logging.getLogger("Orchestrator")

from soc.delta_analyzer import DeltaAnalyzer
from soc.compliance_engine import ComplianceEngine
from soc.control_plane import ControlPlane
import time

from tools.blacklist_tool import BlacklistTool

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
        self.blacklist_tool = BlacklistTool() # Phase 20
        self.aggregator = Aggregator()
        self.llm = LLMManager()
        self.report_gen = ReportGenerator()
        self.client_report_gen = ClientReportGenerator()
        self.email = EmailConnector()
        self.delta_analyzer = DeltaAnalyzer()
        self.compliance_engine = ComplianceEngine()
        self.control_plane = ControlPlane()
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
        logger.info(f"--- [PHASE 20 MONITORING STARTED] ---")
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

        try:
            self.aggregator.ingest(self.blacklist_tool.run(target_ip))
            logger.info("[Orchestrator] Blacklist RBL check completed.")
        except Exception as e:
            logger.error(f"Blacklist check failed: {e}")
            
        if self._is_domain(target_ip):
            try:
                self.aggregator.ingest(self.subfinder_tool.run(target_ip))
            except Exception: pass
            
        final_json = self.aggregator.get_final_payload()
        
        # Step C: Analytics (Delta & Scoring)
        logger.info("\n[STEP C] Running Historical Data Analytics...")
        old_scan = self._get_latest_scan(client_id)
        delta_findings = self.delta_analyzer.analyze(old_scan, final_json)
        compliance_results = self.compliance_engine.calculate_score(final_json, client_id=client_id)
        
        # Step D: LLM Triage
        logger.info("\n[STEP D] AI Triage (Gemini 1.5)...")
        triage_report = self.llm.analyze_scan(final_json, client_context)

        # Step E: Reports (with Analytics)
        report_type = kwargs.get("report_type", "both")
        date_str = time.strftime("%Y-%m")
        client_slug = client_id.lower()
        generated = []

        if report_type in ("internal", "both"):
            logger.info("\n[STEP E.1] Generating Internal SOC Report...")
            md_content = self.report_gen.generate_markdown_report(
                target_ip=target_ip,
                client_id=client_id,
                client_context=client_context,
                scan_data=final_json,
                triage_verdict=triage_report,
                delta_findings=delta_findings,
                compliance_results=compliance_results
            )
            internal_md = f"{client_slug}_internal_{date_str}.md"
            report_path = self.report_gen.save_report(md_content, internal_md)
            generated.append(("internal", report_path))
            logger.info(f"[STEP E.1] Internal report: {report_path}")
            # Also generate internal PDF
            try:
                internal_pdf_name = f"{client_slug}_internal_{date_str}.pdf"
                self.report_gen.generate_pdf_report(
                    target_ip=target_ip,
                    client_id=client_id,
                    client_full_name=client_profile.get("client_name", client_id),
                    score_data=compliance_results,
                    scan_data=final_json,
                    filename=internal_pdf_name,
                    classification="INTERNAL",
                    ai_triage=triage_report
                )
                logger.info(f"[STEP E.1] Internal PDF: {internal_pdf_name}")
            except Exception as e:
                logger.error(f"[STEP E.1] Internal PDF generation failed: {e}")

        if report_type in ("executive", "both"):
            logger.info("\n[STEP E.2] Generating Executive Client Report...")
            try:
                exec_pdf_name = f"{client_slug}_executive_{date_str}.pdf"
                output_dir = os.path.join(BASE_DIR, "reports", "output")
                exec_path = os.path.join(output_dir, exec_pdf_name)
                scan_path_for_exec = os.path.join(self.history_dir, f"{client_slug}_scan_{int(time.time())}.json")
                # Use the already-persisted scan or write temp
                history_files = sorted([f for f in os.listdir(self.history_dir) if f.startswith(f"{client_slug}_scan_")])
                if history_files:
                    scan_path_for_exec = os.path.join(self.history_dir, history_files[-1])
                else:
                    with open(scan_path_for_exec, 'w') as f:
                        json.dump(final_json, f, indent=2)

                self.client_report_gen.generate(
                    scan_path=scan_path_for_exec,
                    client_name=client_profile.get("client_name", client_id),
                    domain=target_ip,
                    output_path=exec_path,
                )
                generated.append(("executive", exec_path))
                logger.info(f"[STEP E.2] Executive PDF: {exec_path}")
            except Exception as e:
                logger.error(f"[STEP E.2] Executive report generation failed: {e}")

        # Step E.3: Email delivery
        client_email = client_profile.get("contact_email")
        soc_email = os.getenv("SOC_INBOX", "")
        for rtype, rpath in generated:
            if rtype == "executive" and client_email:
                self.email.send_report(
                    to=client_email,
                    subject=f"Security Assessment Report — {client_profile.get('client_name', client_id)}",
                    body="Please find your security assessment report attached.",
                    attachment_path=rpath
                )
            elif rtype == "internal" and soc_email:
                self.email.send_report(
                    to=soc_email,
                    subject=f"[SOC] Internal Report — {client_id}",
                    body="Internal SOC report attached.",
                    attachment_path=rpath
                )

        report_path = generated[0][1] if generated else "No reports generated"

        # Step F: Persistence & SOAR
        self._persist_scan(client_id, final_json)
        logger.info("\n[STEP F] Delegating SOAR to Control Plane...")
        try:
            client_name = client_profile.get("client_name", "unknown")
            for finding in final_json.get("findings", []):
                self.control_plane.ingest_alert(
                    client_id=client_name,
                    asset_ip=finding.get("target_ip") or target_ip,
                    finding_type=finding.get("finding_type", "unknown"),
                    severity=finding.get("severity", "low"),
                    source=finding.get("source", "scanner"),
                    raw_finding=finding
                )
        except Exception as e:
            logger.error(f"SOAR delegate failed: {e}")

        return report_path

def add_evidence_arguments(parser):
    """Add evidence verification and export arguments to orchestrator CLI."""
    evidence_group = parser.add_argument_group("Evidence Operations")

    evidence_group.add_argument(
        "--verify-evidence",
        action="store_true",
        help="Verify hash chain integrity for client evidence store"
    )
    evidence_group.add_argument(
        "--export-evidence",
        action="store_true",
        help="Export audit package for auditor review"
    )
    evidence_group.add_argument(
        "--client",
        type=str,
        help="Client ID for evidence operations (e.g., asasEdu)"
    )
    evidence_group.add_argument(
        "--scan-id",
        type=str,
        help="Scan ID to filter evidence export (optional)"
    )

def handle_evidence_command(args) -> int:
    """
    Handle evidence verification and export CLI commands.
    Returns exit code: 0 = success, 1 = failure.
    """
    from soc.evidence_store import EvidenceStore
    import json
    from pathlib import Path
    from datetime import datetime, timezone

    if not args.client:
        print("❌ --client is required for evidence operations")
        return 1

    store = EvidenceStore(args.client)

    if args.verify_evidence:
        print(f"🔍 Verifying evidence chain for client: {args.client}")
        result = store.verify_chain()
        if result:
            print("✅ INTEGRITY OK — chain verified successfully")
            return 0
        else:
            print("❌ CHAIN BROKEN — evidence integrity failure detected")
            return 1

    if args.export_evidence:
        print(f"📦 Exporting audit package for client: {args.client}")
        result = store.verify_chain()
        if not result:
            print("❌ EXPORT BLOCKED — chain integrity failed. Fix chain before exporting.")
            return 1

        package = store.get_audit_package(scan_id=args.scan_id)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_file = Path(f"reports/audit_packages/evidence_export_{args.client}_{timestamp}.json")
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(package, f, ensure_ascii=False, indent=2)

        print(f"✅ Audit package exported: {output_file}")
        print(f"   Records: {package['record_count']}")
        print(f"   Chain integrity: {package['chain_integrity']}")
        print(f"   Format version: {package['export_format_version']} (FROZEN — do not modify)")
        return 0

    return 0

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Synapse Orchestrator - Automated MSSP Triage")
    parser.add_argument("--target", required=False, help="Target IP or Hostname to scan")
    parser.add_argument("--client", required=True, help="Client ID for context retrieval")
    parser.add_argument("--report-type", choices=["internal", "executive", "both"], default="both",
                        help="Report type: internal (SOC), executive (client), or both (default)")
    parser.add_argument("--test-mode", action="store_true", help="Bypass SafetyGuard for local verification")
    add_evidence_arguments(parser)
    
    args = parser.parse_args()
    
    if args.verify_evidence or args.export_evidence:
        sys.exit(handle_evidence_command(args))
        
    if not args.target:
        parser.error("--target is required for normal orchestration runs")

    
    # Configure root logging for CLI
    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    
    orchestrator = Orchestrator()
    try:
        report_path = orchestrator.run_triage(
            args.target, args.client,
            test_mode=args.test_mode,
            report_type=args.report_type
        )
        print(f"\n✅ Triage Complete. Report saved to: {report_path}")
    except Exception as e:
        print(f"\n❌ Orchestration Failed: {e}")
        sys.exit(1)
