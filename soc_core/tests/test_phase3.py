import sys
import logging
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from main_orchestrator import Orchestrator

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger('test_phase3')

def main():
    logger.info("=" * 60)
    logger.info(f"Phase 3 Verification Test Started: Full Pipeline Run")
    logger.info("=" * 60)

    try:
        orc = Orchestrator()
        orc.run_triage("scanme.nmap.org", "TechCo")
        
    except Exception as e:
        logger.error(f"Test failed: {e}")

if __name__ == "__main__":
    main()
