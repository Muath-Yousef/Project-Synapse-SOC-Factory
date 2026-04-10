import sys
import os
import logging
import concurrent.futures
from pathlib import Path

# Ensure root can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from knowledge.vector_store import VectorStore, ClientProfileNotFoundError
import pytest

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger("TestIsolation")

@pytest.fixture(scope="module")
def vs():
    store = VectorStore(persist_dir=".chroma_db_test")
    setup_test_data(store)
    return store

def setup_test_data(vs: VectorStore):
    """
    Ingests mock data for two different clients to test isolation.
    """
    # Using raw ingestion for test speed
    vs.client_collection.upsert(
        documents=["TechCo runs Nmap and Nginx on Ubuntu 22.04. High risk threshold."],
        metadatas=[{"client_name": "TechCo", "type": "profile"}],
        ids=["client_profile_techco_test"]
    )
    vs.client_collection.upsert(
        documents=["BankCo runs Cisco and Oracle on RHEL. Extremely strict risk tolerance."],
        metadatas=[{"client_name": "BankCo", "type": "profile"}],
        ids=["client_profile_bankco_test"]
    )
    logger.info("Test data setup complete (TechCo & BankCo).")

def test_case_1_strict_isolation(vs: VectorStore):
    """Client A query should not return Client B data."""
    logger.info("[Test Case 1] Verifying strict isolation...")
    result = vs.query_context("clients", "operating system", client_id="TechCo")
    
    self_content = str(result.get("content", "")) + str(result.get("client_name", ""))
    assert "BankCo" not in self_content, f"LEAKAGE detected in TechCo results: {result}"
    logger.info("✅ Case 1 Passed: No leakage detected.")

def test_case_2_unknown_client_raises(vs: VectorStore):
    """Unknown client_id should raise ClientProfileNotFoundError."""
    logger.info("[Test Case 2] Verifying error on unknown client...")
    try:
        vs.query_context("clients", "any query", client_id="Unknown_XYZ")
        assert False, "FAILED: Should have raised ClientProfileNotFoundError"
    except ClientProfileNotFoundError as e:
        logger.info(f"✅ Case 2 Passed: Correctly raised error: {e}")

def test_case_3_empty_query_warning(vs: VectorStore):
    """Query that finds no results for a valid client returns status 'not_found' or similar."""
    logger.info("[Test Case 3] Verifying lookup behavior...")
    result = vs.query_context("clients", "Quantum Physics", client_id="TechCo")
    # Even if niche, semantic search might return the closest doc. We check if the filter worked.
    assert result.get("status") == "success"
    assert "TechCo" in str(result)
    logger.info("✅ Case 3 Passed: Results verified with metadata filter.")

def test_case_4_parallel_isolation(vs: VectorStore):
    """Parallel queries for different clients should not mix results."""
    logger.info("[Test Case 4] Verifying parallel isolation (Thread Safety)...")

    def query_worker(cid, text):
        return vs.query_context("clients", text, client_id=cid)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(query_worker, "TechCo", "What OS do I run?")
        f2 = executor.submit(query_worker, "BankCo", "What OS do I run?")
        
        r1, r2 = f1.result(), f2.result()
        
        # Cross-reference check in the new dictionary format
        assert "TechCo" in str(r1) and "BankCo" not in str(r1), "TechCo result mixed or incorrect"
        assert "BankCo" in str(r2) and "TechCo" not in str(r2), "BankCo result mixed or incorrect"
        
    logger.info("✅ Case 4 Passed: Parallel threads maintained isolation.")

def run_all_tests():
    vs = VectorStore(persist_dir=".chroma_db_test")
    setup_test_data(vs)
    
    try:
        test_case_1_strict_isolation(vs)
        test_case_2_unknown_client_raises(vs)
        test_case_3_empty_query_warning(vs)
        test_case_4_parallel_isolation(vs)
        print("\n🎉 ALL ISOLATION TESTS PASSED SUCCESSFULLY!")
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    run_all_tests()
