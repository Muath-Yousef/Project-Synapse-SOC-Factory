import sys
import logging
import json
import os

# Add parent directory to path to allow imports when running script directly from tests/
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tools.nmap_tool import NmapTool
from parsers.nmap_parser import NmapParser
from parsers.aggregator import Aggregator

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger('test_phase1')

def main():
    target = "scanme.nmap.org"
    logger.info("=" * 60)
    logger.info(f"Phase 1 Verification Test Started: Data Ingestion Pipeline")
    logger.info(f"Target: {target}")
    logger.info("=" * 60)

    try:
        # Step 1: Execute Tool
        logger.info("\n--- 1. Executing NmapWrapper ---")
        nmap_tool = NmapTool()
        logger.info(f"Tool Description: {nmap_tool.get_description()}")
        
        raw_xml = nmap_tool.run(target, profile="quick")
        logger.info(f"Successfully generated RAW XML output (Length: {len(raw_xml)} bytes).")
        
        # Step 2: Parse Data
        logger.info("\n--- 2. Parsing XML -> JSON ---")
        parser = NmapParser()
        parsed_data = parser.parse(raw_xml)
        logger.info("XML successfully normalized into unified JSON dictionary format.")
        
        # Step 3: Aggregate
        logger.info("\n--- 3. Aggregating Target Data ---")
        aggregator = Aggregator()
        aggregator.ingest(parsed_data)
        
        final_payload = aggregator.get_final_payload()
        
        logger.info("\n🏆 Final System Output (Ready for LLM Context):")
        print(json.dumps(final_payload, indent=2))
        
    except Exception as e:
        logger.error(f"Test failed: {e}")

if __name__ == "__main__":
    main()
