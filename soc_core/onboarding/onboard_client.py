#!/usr/bin/env python3
import sys, os, yaml, argparse, logging
sys.path.insert(0, '/media/kyrie/VMs1/Cybersecurity_Tools_Automation')
os.chdir('/media/kyrie/VMs1/Cybersecurity_Tools_Automation')
from pathlib import Path
from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("onboarding")

from datetime import datetime, timedelta

TIER_CONFIGS = {
    "soc_lite"     : {"log_cap_gb_day": 2,  "scan_frequency": "monthly", "compliance": [], "price": 500},
    "soc_standard" : {"log_cap_gb_day": 10, "scan_frequency": "weekly",  "compliance": ["NCA_ECC"], "price": 1500},
    "soc_pro"      : {"log_cap_gb_day": 20, "scan_frequency": "weekly",  "compliance": ["NCA_ECC", "ISO_27001"], "price": 3000},
    "soc_grc"      : {"log_cap_gb_day": 30, "scan_frequency": "weekly",  "compliance": ["NCA_ECC", "ISO_27001", "UAE_PDPL"], "price": 5000},
}

INDUSTRY_TECH_STACKS = {
    "Technology"  : ["Nginx", "Ubuntu", "Docker", "Node.js", "Python"],
    "Banking"     : ["Apache", "Ubuntu", "OpenSSH", "Oracle"],
    "Healthcare"  : ["Apache", "Windows Server", "OpenSSH"],
    "E-commerce"  : ["Nginx", "WordPress", "MySQL", "PHP"],
    "Default"     : ["Apache", "Nginx", "Ubuntu", "OpenSSH"],
}

def build_client_profile(name, target, email, industry, tier, whitelisted_ips=None):
    tier_config = TIER_CONFIGS.get(tier, TIER_CONFIGS["soc_standard"])
    tech_stack = INDUSTRY_TECH_STACKS.get(industry, INDUSTRY_TECH_STACKS["Default"])
    
    # Financial Dates
    start = datetime.now()
    end = start + timedelta(days=365)
    
    return {
        "client_name": name,
        "industry": industry,
        "primary_target": target,
        "contact_email": email,
        "service_tier": tier,
        "log_cap_gb_day": tier_config["log_cap_gb_day"],
        "scan_frequency": tier_config["scan_frequency"],
        "compliance_requirements": tier_config["compliance"],
        "tech_stack_keywords": tech_stack,
        "whitelisted_ips": whitelisted_ips or [],
        "infrastructure": {"os": [], "web_server": [], "platform": []},
        "security_profile": {"risk_tolerance": "low"},
        "billing": {
            "monthly_fee": tier_config["price"],
            "currency": "USD",
            "contract_start": start.strftime("%Y-%m-%d"),
            "contract_end": end.strftime("%Y-%m-%d"),
            "status": "active"
        }
    }

def save_profile(profile, profiles_dir="knowledge/client_profiles"):
    Path(profiles_dir).mkdir(parents=True, exist_ok=True)
    client_id = profile["client_name"].lower().replace(" ", "_")
    filepath = f"{profiles_dir}/{client_id}.yaml"
    if Path(filepath).exists():
        logger.warning(f"Profile already exists: {filepath} — overwriting")
    with open(filepath, "w") as f:
        yaml.dump(profile, f, default_flow_style=False, allow_unicode=True)
    logger.info(f"✅ Profile saved: {filepath}")
    return filepath

def ingest_to_vector_store(client_name, filepath):
    try:
        from knowledge.vector_store import VectorStore
        vs = VectorStore()
        vs.ingest_client_profile(filepath)
        logger.info(f"✅ Ingested into ChromaDB: {client_name}")
    except Exception as e:
        logger.error(f"ChromaDB ingestion failed for {client_name}: {e}")

def onboard(name, target, email, industry, tier, whitelisted_ips=None):
    logger.info(f"=== Onboarding: {name} ===")
    profile = build_client_profile(name, target, email, industry, tier, whitelisted_ips)
    filepath = save_profile(profile)
    ingest_to_vector_store(name, filepath)
    logger.info(f"=== Complete: {name} — Tier: {tier} ===")
    return filepath

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Synapse Client Onboarding")
    parser.add_argument("--name",     required=True)
    parser.add_argument("--target",   required=True)
    parser.add_argument("--email",    required=True)
    parser.add_argument("--industry", default="Technology", choices=list(INDUSTRY_TECH_STACKS.keys()))
    parser.add_argument("--tier",     default="soc_standard", choices=list(TIER_CONFIGS.keys()))
    parser.add_argument("--whitelist", nargs="*", default=[])
    args = parser.parse_args()
    onboard(args.name, args.target, args.email, args.industry, args.tier, args.whitelist)
