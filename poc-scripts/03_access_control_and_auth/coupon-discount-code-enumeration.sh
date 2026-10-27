#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Coupon/Discount Code Enumeration
# Description: Tests for predictable or enumerable discount codes
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Coupon/Discount Code Enumeration\033[0m"
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
# common coupon patterns
CODES="WELCOME10 SAVE10 SAVE20 DISCOUNT10 FIRST10 OFF10 NEWUSER VIP ADMIN TEST FREE"
for EP in "api/coupon" "api/v1/coupon" "api/discount" "api/v1/discount" "api/promo" "api/v1/promo" "coupon" "api/validate-coupon"; do
  for C in $CODES; do
    R=$(curl -s -X POST -H "Content-Type: application/json" -d "{\"code\":\"$C\"}" --max-time 8 "$T/$EP" 2>/dev/null | head -c 300)
    if echo "$R" | grep -qi "valid\|applied\|discount.*[0-9]"; then
      emit "{\"title\":\"Active coupon code discovered: $C\",\"severity\":\"low\",\"description\":\"Coupon code $C is valid at /$EP. Predictable codes allow discount abuse.\",\"remediation\":\"Use random non-guessable codes. Rate limit validation endpoint.\",\"cweId\":\"CWE-330\",\"owaspCategory\":\"A04:2025-Insecure Design\"}"
    fi
  done
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
