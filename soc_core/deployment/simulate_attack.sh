#!/bin/bash
# simulate_attack.sh - Authentic Wazuh SIEM Simulation Payload

TARGET_IP=$1
if [ -z "$TARGET_IP" ]; then
    echo "Usage: ./simulate_attack.sh <NODE_A_IP>"
    exit 1
fi

echo "[*] Triggering SSH Brute Force Authentication logs on $TARGET_IP..."
echo "Expected: Wazuh parses these logs into Auth Failure Rule (usually Level 10/12)"

ssh root@$TARGET_IP << 'EOF'
for i in $(seq 1 10); do
  logger "Failed password for invalid user from 8.8.8.8 port 22 ssh2"
done
EOF

echo "[*] Execution complete. Awaiting Wazuh SIEM processing -> Webhook trigger."
