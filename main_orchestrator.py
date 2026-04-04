import logging
import json
import os
import sys

# Define base path to ensure relative imports from root directory work inside testing frameworks
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, BASE_DIR)

from tools.nmap_tool import NmapTool
from parsers.nmap_parser import NmapParser
from parsers.aggregator import Aggregator
from knowledge.vector_store import VectorStore
from core.llm_manager import LLMManager
from reports.report_generator import ReportGenerator

logger = logging.getLogger("Orchestrator")

class Orchestrator:
    def __init__(self):
        # Initialize the pipeline components
        self.vector_store = VectorStore(persist_dir=os.path.join(BASE_DIR, ".chroma_db_test")) 
        self.nmap_tool = NmapTool()
        self.parser = NmapParser()
        self.aggregator = Aggregator()
        self.llm = LLMManager()
        self.report_gen = ReportGenerator()

    def run_triage(self, target_ip: str, client_id: str):
        logger.info(f"--- [PHASE 5 ORCHESTRATION STARTED] ---")
        logger.info(f"Target: {target_ip} | Client ID: {client_id}")

        # Step A: Fetch Context
        logger.info("\n[STEP A] Grabbing Context (Memory Retrieval)...")
        context_results = self.vector_store.query_context("clients", client_id, n_results=1)
        client_context = context_results[0] if context_results else "No Context Found"
        logger.info(f"Context Snippet: {client_context[:100]}..." if client_context != "No Context Found" else "No Context snippet.")

        # Step B: Scan & Parse
        logger.info(f"\n[STEP B] Standardizing Data (Nmap Scanner -> Parser -> Aggregator)...")
        raw_xml = self.nmap_tool.run(target_ip, profile="quick")
        parsed_dict = self.parser.parse(raw_xml)
        self.aggregator.ingest(parsed_dict)
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
        return report_path
