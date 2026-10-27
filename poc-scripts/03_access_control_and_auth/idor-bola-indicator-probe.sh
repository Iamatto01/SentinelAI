#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        IDOR / BOLA Indicator Probe
# Description: Tests sequential resource IDs for access control
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: IDOR / BOLA Indicator Probe\033[0m"
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
# find API resource endpoints
PATHS="api/v1/users/1 api/v1/users/2 api/v1/orders/1 api/v1/orders/2 api/v1/documents/1 api/v1/profile/1 api/v1/accounts/1 api/v1/invoices/1 api/v1/tickets/1 api/v1/messages/1"
for P in $PATHS; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ]; then
    BODY=$(curl -s --max-time 8 "$T/$P" 2>/dev/null | head -c 500)
    # if data returns without auth header, it's likely IDOR
    if echo "$BODY" | grep -q "id\|name\|email\|data"; then
      emit "{\"title\":\"Potential IDOR/BOLA: /$P accessible without auth\",\"severity\":\"high\",\"description\":\"Resource endpoint /$P returns data (HTTP 200) without authentication. Sequential IDs allow mass data enumeration.\",\"remediation\":\"Enforce authentication and object-level authorization on every resource endpoint.\",\"cweId\":\"CWE-639\",\"owaspCategory\":\"A01:2025-Broken Access Control\"}"
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
