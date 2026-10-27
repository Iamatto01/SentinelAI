#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Common Service Port Scan (top 20)
# Description: TCP connect scan on high-risk ports — management, DB, mail
# Severity:    HIGH
# Category:    Network, Cloud & Infrastructure Security
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Common Service Port Scan (top 20)\033[0m"
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
PORTS="21 22 23 25 53 80 110 143 443 445 993 995 1433 1521 2049 3306 3389 5432 5900 6379 8080 8443 9200 11211 27017"
for PORT in $PORTS; do
  (timeout 3 bash -c "echo >/dev/tcp/$HOST/$PORT" 2>/dev/null &&     emit "{\"title\":\"Open port: $PORT\",\"severity\":\"info\",\"description\":\"Port $PORT is open on $HOST. $([ $PORT = 22 ] && echo 'SSH service.' || { [ $PORT = 3306 ] && echo 'MySQL database.' || { [ $PORT = 5432 ] && echo 'PostgreSQL database.' || { [ $PORT = 6379 ] && echo 'Redis cache.' || { [ $PORT = 27017 ] && echo 'MongoDB database.' || { [ $PORT = 3389 ] && echo 'RDP remote desktop.' || { [ $PORT = 9200 ] && echo 'Elasticsearch.' || echo 'Service.'; }; }; }; }; }; }) Verify it should be internet-exposed.\",\"remediation\":\"Close unnecessary ports. Restrict database and management services to internal networks.\",\"cweId\":\"CWE-200\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}") &
done
wait

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
