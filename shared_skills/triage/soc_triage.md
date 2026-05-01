# Skill: SOC Triage & Alert Analysis

## When to Use
Use this skill when a new security alert (e.g., from Wazuh) is received or when performing a proactive threat hunt across system logs.

## Core Knowledge
- **Wazuh Alert Structure**: Rules, Levels (0-15), Agent IDs, and Full Logs.
- **Severity Scoring**:
  - Level 12+: Critical (Immediate Response)
  - Level 7-11: High (Triage within 1 hour)
  - Level 3-6: Medium/Low (Batch processing)
- **Common False Positives**: Scheduled backups, administrative SSH logins from known IPs, and automated software updates.

## Investigation Patterns
1. **Source Validation**: Is the source IP internal or external? Is it on a known whitelist?
2. **Impact Assessment**: Which host is targeted? Does it contain sensitive data?
3. **Correlation**: Are there multiple alerts from the same source in the last 10 minutes?
4. **Tool Usage**: Use `cyber_tools_server` to check IP reputation on VirusTotal.

## Decision Flow
- IF malicious IP confirmed -> Trigger `incident_response` skill.
- IF false positive -> Log reason and close task.
- IF ambiguous -> Escalate to Human-in-the-Loop (HITL).
