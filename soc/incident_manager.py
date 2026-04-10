#!/usr/bin/env python3
"""
soc/incident_manager.py — Synapse Control Plane CLI (Phase 24)

Analyst interface for the Control Plane.
Allows listing open incidents, advancing states, and flagging false positives.
"""

import argparse
import sys
from soc.control_plane import ControlPlane

def main():
    parser = argparse.ArgumentParser(description="Synapse Incident Manager")
    parser.add_argument("--client", help="Client ID to filter by")
    
    subparsers = parser.add_subparsers(dest="action", required=True)
    
    # List incidents
    list_parser = subparsers.add_parser("list", help="List open incidents")
    
    # Update state
    update_parser = subparsers.add_parser("update", help="Update incident state")
    update_parser.add_argument("incident_id", help="Incident ID (e.g. INC-20260410-0001)")
    update_parser.add_argument("state", choices=["open", "investigating", "contained", "closed", "false_positive"])
    update_parser.add_argument("--note", default="", help="Optional context note")
    
    # Flag FP
    fp_parser = subparsers.add_parser("flag-fp", help="Flag an alert as a False Positive")
    fp_parser.add_argument("alert_id", help="Alert ID")

    # Rule Health
    rules_parser = subparsers.add_parser("rules", help="View detection rule health")

    args = parser.parse_args()
    cp = ControlPlane()

    if args.action == "list":
        if not args.client:
            print("❌ --client is required to list incidents.")
            sys.exit(1)
        incidents = cp.get_open_incidents(args.client)
        if not incidents:
            print(f"✅ No open incidents for {args.client}")
            return
            
        print(f"=== Open Incidents for {args.client} ===")
        for inc in incidents:
            print(f"[{inc['id']}] {inc['severity'].upper()} | {inc['state']} | {inc['title']}")

    elif args.action == "update":
        try:
            cp.update_incident_state(args.incident_id, args.state, actor="analyst_cli", note=args.note)
            print(f"✅ Successfully updated {args.incident_id} to '{args.state}'")
        except Exception as e:
            print(f"❌ Failed to update incident: {e}")

    elif args.action == "flag-fp":
        try:
            cp.flag_false_positive(args.alert_id, analyst="analyst_cli")
            print(f"✅ Alert {args.alert_id} marked as False Positive. Associated rules tuned.")
        except Exception as e:
            print(f"❌ Failed to flag FP: {e}")

    elif args.action == "rules":
        health = cp.get_rule_health()
        print("=== Detection Rule Health ===")
        print(f"{'Finding Type':<25} | {'Severity':<10} | {'Weight':<8} | {'FP':<4} | {'TP':<4}")
        print("-" * 65)
        for r in health:
            flag = "⚠️" if r["weight"] < 0.4 else "✅"
            print(f"{r['finding_type']:<25} | {r['severity']:<10} | {r['weight']:<8.3f} | {r['fp_count']:<4} | {r['tp_count']:<4} {flag}")


if __name__ == "__main__":
    main()
