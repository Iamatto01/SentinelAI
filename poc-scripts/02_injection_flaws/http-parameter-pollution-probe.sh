#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        HTTP Parameter Pollution Probe
# Description: Tests duplicate parameter handling for logic bypass
# Severity:    MEDIUM
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: HTTP Parameter Pollution Probe\033[0m"
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
PARAMS="amount price quantity discount role user id type status"
for P in $PARAMS; do
  # send duplicate params with different values
  R1=$(curl -s --max-time 10 "$T?$P=100&$P=1" 2>/dev/null | head -c 2000)
  R2=$(curl -s --max-time 10 "$T?$P=100" 2>/dev/null | head -c 2000)
  if [ "$R1" != "$R2" ] && [ -n "$R1" ]; then
    # check if the second (lower) value was used — potential price manipulation
    if echo "$R1" | grep -q "1" && ! echo "$R2" | grep -q "\<1\<"; then
      emit "{\"title\":\"HTTP parameter pollution: ?$P=\",\"severity\":\"medium\",\"description\":\"Duplicate $P parameters produce different responses. Backend may use first/last value inconsistently — price or role manipulation possible.\",\"remediation\":\"Reject duplicate parameters. Use consistent parsing across all layers.\",\"cweId\":\"CWE-235\",\"owaspCategory\":\"A03:2025-Injection\"}"
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
