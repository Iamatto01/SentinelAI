#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Authentication Timing Side-Channel
# Description: Measures response time differential for valid vs invalid usernames
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Authentication Timing Side-Channel\033[0m"
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
for EP in "login" "api/login" "api/auth/login" "api/v1/login"; do
  # measure with likely-valid username
  T1=0; T2=0
  for I in 1 2 3; do
    S=$(date +%s%N)
    curl -s -o /dev/null -X POST -H "Content-Type: application/json" -d '{"username":"admin","password":"wrongpass"}' --max-time 15 "$T/$EP" 2>/dev/null
    E=$(date +%s%N)
    T1=$(( T1 + (E - S) / 1000000 ))
    S=$(date +%s%N)
    curl -s -o /dev/null -X POST -H "Content-Type: application/json" -d '{"username":"zznonexistentzz","password":"wrongpass"}' --max-time 15 "$T/$EP" 2>/dev/null
    E=$(date +%s%N)
    T2=$(( T2 + (E - S) / 1000000 ))
  done
  T1=$(( T1 / 3 )); T2=$(( T2 / 3 ))
  DIFF=$(( T1 - T2 ))
  if [ $DIFF -gt 200 ]; then
    emit "{\"title\":\"Username enumeration via timing: /$EP\",\"severity\":\"medium\",\"description\":\"Login with 'admin' takes ${T1}ms vs ${T2}ms for invalid user (${DIFF}ms differential). Password hashing only runs for valid usernames — username oracle.\",\"remediation\":\"Run password hashing even for invalid usernames. Constant-time responses.\",\"cweId\":\"CWE-208\",\"owaspCategory\":\"A07:2025-Identification and Authentication Failures\"}"
    break
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
