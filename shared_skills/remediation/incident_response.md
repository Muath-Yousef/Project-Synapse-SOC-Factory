# Skill: Incident Response & Remediation

## When to Use
Use this skill after a security threat has been confirmed during triage. This skill guides the containment and eradication phases.

## Core Knowledge
- **Containment Tactics**:
  - Network Isolation (Blocking IPs/Ports)
  - Host Isolation (via Wazuh/EDR)
  - Account Lockout (LDAP/AD/Cloud)
- **Eradication**: Killing malicious processes, deleting web shells, and patching vulnerabilities.
- **Evidence Preservation**: Always take a snapshot or log the state BEFORE making changes.

## Remediation Patterns
1. **Network Block**:
   - Use `terminal_server` to update `iptables` or cloud security groups.
   - Example: `iptables -A INPUT -s [MALICIOUS_IP] -j DROP`
2. **Process Termination**:
   - Identify PID via `lsof` or `ps`.
   - Terminate with `kill -9`.
3. **Password Reset**:
   - Trigger automated password reset workflows for compromised accounts.

## Recovery Steps
1. Verify system integrity via `verify_evidence_integrity`.
2. Monitor logs for 24 hours for signs of lateral movement.
3. Generate incident report using `generate_audit_package`.
