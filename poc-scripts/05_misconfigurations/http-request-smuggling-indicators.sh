#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        HTTP Request Smuggling Indicators
# Description: Detects CL.TE / TE.CL discrepancies via differential responses
# Severity:    HIGH
# Category:    Web Server & HTTP Misconfigurations
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: HTTP Request Smuggling Indicators\033[0m"
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
# CL.TE test: send conflicting Content-Length and Transfer-Encoding
# if server processes both differently, timing differential appears
S1=$(date +%s%N)
curl -s -o /dev/null --max-time 15 -X POST -H "Content-Type: application/x-www-form-urlencoded" -H "Transfer-Encoding: chunked" -d "0\r\n\r\n" "$T" 2>/dev/null
E1=$(date +%s%N)
D1=$(( (E1 - S1) / 1000000 ))
# normal request baseline
S2=$(date +%s%N)
curl -s -o /dev/null --max-time 15 -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "x=1" "$T" 2>/dev/null
E2=$(date +%s%N)
D2=$(( (E2 - S2) / 1000000 ))
DIFF=$(( D1 - D2 ))
if [ $DIFF -gt 5000 ]; then
  emit "{\"title\":\"HTTP request smuggling indicator (timing differential)\",\"severity\":\"high\",\"description\":\"Chunked encoding request shows ${DIFF}ms delay vs ${D2}ms baseline. Front-end and back-end servers may parse the request differently — smuggling possible.\",\"remediation\":\"Normalize requests at proxy layer. Reject both Content-Length and Transfer-Encoding headers together.\",\"cweId\":\"CWE-444\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
