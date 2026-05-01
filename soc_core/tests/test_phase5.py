import sys
import logging
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from main_orchestrator import Orchestrator

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger('test_phase5')

def main():
    logger.info("=" * 60)
    logger.info(f"Phase 5 Verification Test Started: Executive Reporting Generation")
    logger.info("=" * 60)

    try:
        orc = Orchestrator()
        
        # Will run all steps and output to Markdown
        report_path = orc.run_triage("scanme.nmap.org", "TechCo")
        
        # Verify Report creation
        if report_path and os.path.exists(report_path):
            logger.info(f"\n✅ Success! Report File found at {report_path}")
            
            logger.info("\n" + "=" * 20 + " RAW MARKDOWN CONTENT " + "=" * 20)
            with open(report_path, "r", encoding="utf-8") as f:
                print(f.read())
            logger.info("=" * 65)
        else:
            logger.error(f"\n❌ Failure. Report file was not created. Path returned: {report_path}")

    except Exception as e:
        logger.error(f"Test failed: {e}")

if __name__ == "__main__":
    main()
