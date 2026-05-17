import sys
import yaml
import json
from pathlib import Path
from fastapi.testclient import TestClient

# Insert soc_core to path
sys.path.insert(0, '/home/kyrie/Projects/Project-Synapse-SOC-Factory/soc_core')

# Mock environment before importing app
import os
os.environ["STRIPE_WEBHOOK_SECRET"] = "whsec_test"
os.environ["PORTAL_SECRET_KEY"] = "test-secret"

from portal.app import app

client = TestClient(app)

# 1. Setup a test client profile
profile_path = Path("/home/kyrie/Projects/Project-Synapse-SOC-Factory/soc_core/knowledge/client_profiles/test_billing_client.yaml")
profile_path.parent.mkdir(parents=True, exist_ok=True)
with open(profile_path, "w") as f:
    yaml.dump({
        "domain": "test.com",
        "portal_api_key_hash": "dummy_hash",
        "stripe_customer_id": "cus_123"
    }, f)

# Create a token for the client
from portal.app import create_access_token
token = create_access_token("test_billing_client")
headers = {"Authorization": f"Bearer {token}"}

# 2. Test gating: /scan/request should fail with 402
print("Testing Gated Endpoint...")
res = client.post("/scan/request", headers=headers)
print(f"Status Code without subscription: {res.status_code}")
assert res.status_code == 402

# 3. Test Webhook to activate subscription
# Instead of signing the payload, we'll patch stripe.Webhook.construct_event temporarily
import stripe
def mock_construct_event(payload, sig, secret):
    return {
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "client_reference_id": "test_billing_client",
                "subscription": "sub_123",
                "customer": "cus_123"
            }
        }
    }
stripe.Webhook.construct_event = mock_construct_event

print("Simulating Webhook...")
res = client.post("/billing/webhook", json={})
print(f"Webhook Status: {res.status_code}")
assert res.status_code == 200

# Verify YAML is updated
with open(profile_path, "r") as f:
    profile = yaml.safe_load(f)
    print(f"Updated Profile: {profile}")
    assert profile.get("subscription_status") == "active"

# 4. Test gating: /scan/request should now succeed (or fail differently if domain scan fails, but not 402)
# Since the orchestrator is run via subprocess, it might actually launch. Let's mock subprocess.Popen
import subprocess
class MockPopen:
    def __init__(self, *args, **kwargs):
        pass
subprocess.Popen = MockPopen

print("Testing Gated Endpoint with Active Subscription...")
res = client.post("/scan/request", headers=headers)
print(f"Status Code with subscription: {res.status_code}")
assert res.status_code == 200

# Cleanup
profile_path.unlink()
print("Test Passed!")
