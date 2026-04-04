import sys
import logging
import os

# Add parent directory to path to allow imports when running script directly from tests/
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from knowledge.vector_store import VectorStore

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger('test_phase2')

def main():
    logger.info("=" * 60)
    logger.info(f"Phase 2 Verification Test Started: RAG & System Memory (ChromaDB)")
    logger.info("=" * 60)

    try:
        # Initialize VectorStore
        logger.info("\n--- 1. Initializing Vector Store ---")
        store = VectorStore(persist_dir=".chroma_db_test")
        
        # Path to data
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        techco_path = os.path.join(base_dir, "knowledge", "client_profiles", "techco.yaml")
        nca_path = os.path.join(base_dir, "knowledge", "compliance_frameworks", "nca_controls.json")
        
        # Ingest Data
        logger.info("\n--- 2. Ingesting Data (Client Profiles & Controls) ---")
        store.ingest_client_profile(techco_path)
        store.ingest_compliance_framework(nca_path)
        
        # Query Context
        logger.info("\n--- 3. Testing Semantic Context Retrieval ---")
        query = "What web server technology does TechCo use?"
        logger.info(f"Query: '{query}'")
        
        results = store.query_context("clients", query, n_results=1)
        
        logger.info("\n🏆 Context Retrieved:")
        if results:
            for i, res in enumerate(results):
                print(f"\n[Result {i+1}]:\n{res}")
                
                # Check for success condition
                if "Nginx" in res:
                    logger.info("✅ Success! 'Nginx' found in retrieved context.")
                else:
                    logger.warning("❌ Failed. Context retrieved but missing expected 'Nginx' mention.")
        else:
            logger.error("❌ Failed to retrieve context.")

        query2 = "What are the rules for encrypting data?"
        logger.info(f"\nQuery 2: '{query2}'")
        results2 = store.query_context("compliance", query2, n_results=1)
        
        if results2:
            for i, res in enumerate(results2):
                print(f"[Result {i+1}]:\n{res}")
            logger.info("✅ Success! Compliance data retrieved.")

    except Exception as e:
        logger.error(f"Test failed: {e}")

if __name__ == "__main__":
    main()
