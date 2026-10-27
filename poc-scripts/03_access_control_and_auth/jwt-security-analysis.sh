#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        JWT Security Analysis
# Description: Finds JWT tokens in responses and checks for weak configurations
# Severity:    MEDIUM
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: JWT Security Analysis\033[0m"
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
# Try to get a token from common auth endpoints
for EP in "api/login" "api/auth/login" "api/v1/login" "api/v1/auth/login" "login" "auth/login" "api/token" "api/v1/token"; do
  RESP=$(curl -s -X POST -H "Content-Type: application/json" -d '{"username":"test","email":"test@test.com","password":"test"}' --max-time 10 "$T/$EP" 2>/dev/null)
  TOKEN=$(echo "$RESP" | grep -oP 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' | head -1)
  if [ -n "$TOKEN" ]; then
    # decode header
    HDR=$(echo "$TOKEN" | cut -d. -f1 | tr '_-' '/+' | base64 -d 2>/dev/null)
    ALG=$(echo "$HDR" | grep -o '"alg":"[^"]*"' | cut -d'"' -f4)
    if [ "$ALG" = "none" ]; then
      emit "{\"title\":\"JWT uses alg:none — signature bypass\",\"severity\":\"critical\",\"description\":\"JWT token issued with alg:none. Attackers can forge arbitrary tokens without a key.\",\"remediation\":\"Enforce HS256 or RS256. Reject alg:none tokens.\",\"cweId\":\"CWE-347\",\"owaspCategory\":\"A02:2025-Cryptographic Failures\"}"
    elif [ "$ALG" = "HS256" ]; then
      emit "{\"title\":\"JWT uses HS256 (symmetric)\",\"severity\":\"info\",\"description\":\"JWT tokens use HS256. If the secret is weak, tokens can be forged. Found at /$EP\",\"remediation\":\"Use a strong secret (256-bit+) or switch to RS256/ES256.\",\"cweId\":\"CWE-326\",\"owaspCategory\":\"A02:2025-Cryptographic Failures\"}"
    fi
    # check expiry claim
    PAYLOAD=$(echo "$TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null)
    if ! echo "$PAYLOAD" | grep -q "exp"; then
      emit "{\"title\":\"JWT token has no expiry claim\",\"severity\":\"high\",\"description\":\"JWT token from /$EP lacks exp claim — tokens never expire, stolen tokens are permanent.\",\"remediation\":\"Add exp claim with short lifetime (15-60 min).\",\"cweId\":\"CWE-613\",\"owaspCategory\":\"A07:2025-Identification and Authentication Failures\"}"
    fi
    break
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
