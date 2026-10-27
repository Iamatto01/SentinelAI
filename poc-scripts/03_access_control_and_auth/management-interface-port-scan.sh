#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Management Interface Port Scan
# Description: Scans non-standard ports for admin panels and management UIs
# Severity:    HIGH
# Category:    Broken Access Control & Authentication
# Language:    bash
# ============================================================================

# Target argument handling: allow positional arg $1 or env var TARGET
TARGET="${1:-${TARGET:-}}"
SCAN_ID="${SCAN_ID:-standalone_poc_test}"
DEPTH="${DEPTH:-standard}"

if [ -z "$TARGET" ]; then
  echo -e "\033[1;31m[-] Error: Missing TARGET argument.\033[0m"
  echo -e "\033[1;33m[*] Usage:   $0 <target_url_or_ip>\033[0m"
  echo -e "\033[1;34m[*] Example: $0 https://example.com\033[0m"
  exit 1
fi

# Normalize URL: remove trailing slash
TARGET="${TARGET%/}"

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Management Interface Port Scan\033[0m"
echo -e "\033[1;34m[*] Target: $TARGET\033[0m"
echo ""

# Standard emit handler for standalone terminal execution
emit() {
  echo -e "\033[1;32m[+] VULNERABILITY CONFIRMED / FINDING EMITTED:\033[0m"
  echo "$1" | python3 -m json.tool 2>/dev/null || echo "    $1"
}

# --- Core PoC Execution ---
emit() { printf '%s\n' "$1"; }
HOST=$(echo "$TARGET" | sed 's|https\?://||' | cut -d/ -f1 | cut -d: -f1)
PORTS="10000 2082 2083 2086 2087 2095 2096 3000 3001 4000 4848 5000 5601 7001 7002 8000 8008 8009 8081 8082 8083 8088 8090 8180 8443 8888 9000 9001 9090 9443 9999 10000 15672 55555"
for PORT in $PORTS; do
  (timeout 3 bash -c "echo >/dev/tcp/$HOST/$PORT" 2>/dev/null &&     emit "{\"title\":\"Non-standard port open: $PORT\",\"severity\":\"low\",\"description\":\"Port $PORT is open — often management panels (cPanel=2082/2083, WebLogic=7001, Kibana=5601, RabbitMQ=15672, Jenkins=8080). Verify exposure is intentional.\",\"remediation\":\"Restrict management interfaces to VPN/internal access.\",\"cweId\":\"CWE-200\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}") &
done
wait

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
