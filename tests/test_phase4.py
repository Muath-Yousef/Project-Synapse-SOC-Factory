import sys
import logging
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from agents.meta_agent import MetaAgent
from tools.tool_registry import ToolRegistry

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger('test_phase4')

def main():
    logger.info("=" * 60)
    logger.info(f"Phase 4 Verification Test Started: Meta-Agent Auto-Generation")
    logger.info("=" * 60)

    try:
        # 1. Instantiate MetaAgent
        logger.info("\n--- 1. Instantiating MetaAgent ---")
        meta_agent = MetaAgent()
        
        # 2. Generate Nikto Wrapper
        logger.info("\n--- 2. Requesting new tool 'nikto' ---")
        code = meta_agent.generate_tool_wrapper("nikto", "Web server vulnerability scanner")
        
        # 3. Write to Disk
        logger.info("\n--- 3. Writing generated code to disk ---")
        meta_agent.write_tool_to_disk(code, "nikto_tool.py")
        
        # 4. Auto-Discovery
        logger.info("\n--- 4. Checking ToolRegistery Auto-Discovery ---")
        registry = ToolRegistry()
        tools = registry.list_tools()
        
        logger.info(f"\n🏆 Final Available Tools Discovered:")
        for t in tools:
            logger.info(f"- {t}")
            
        if "NiktoTool" in tools:
            logger.info("\n✅ Success! Meta-Agent successfully authored code that was seamlessly auto-discovered by the kernel!")
        else:
            logger.error("\n❌ Failure. NiktoTool was not discovered in the registry.")
        
    except Exception as e:
        logger.error(f"Test failed: {e}")

if __name__ == "__main__":
    main()
