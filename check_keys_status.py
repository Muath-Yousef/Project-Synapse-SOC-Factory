import os
import sys

# Add packages/ide-engine to path to import core
sys.path.append(os.path.join(os.getcwd(), "packages", "ide-engine"))

from core.key_pool import APIKeyPool

def check_keys():
    pool = APIKeyPool()
    print(f"--- Key Pool Diagnostics ---")
    print(f"Config Path: {pool.config_path}")
    
    if not pool.config.services:
        print("❌ No services found in config!")
        return

    for service, data in pool.config.services.items():
        print(f"\nService: {service.upper()}")
        for i, key in enumerate(data.keys):
            status_icon = "✅" if key.status == "active" else "⏳" if key.status == "cooldown" else "❌"
            masked_value = f"{key.value[:8]}...{key.value[-4:]}"
            retry_info = f" (Retry after: {key.retry_after})" if key.retry_after else ""
            print(f"  {i+1}. {status_icon} {key.status.upper()}: {masked_value}{retry_info}")

if __name__ == "__main__":
    check_keys()
