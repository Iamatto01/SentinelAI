#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        HTTP Protocol Version & Features
# Description: Checks HTTP/2 support, connection handling, keep-alive
# Severity:    INFO
# Category:    Framework & API Security (Laravel, WordPress, Spring, GraphQL)
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: HTTP Protocol Version & Features\033[0m"
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
# HTTP/2 support
H2=$(curl -s -I --http2 -o /dev/null -w "%{http_version}" --max-time 10 "$T" 2>/dev/null)
if [ "$H2" = "2" ]; then
  emit "{\"title\":\"HTTP/2 supported\",\"severity\":\"info\",\"description\":\"Server supports HTTP/2. Note: HTTP/2 request smuggling vectors differ from HTTP/1.1.\",\"remediation\":\"Informational.\",\"cweId\":\"CWE-200\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi
# check for connection header handling
H=$(curl -s -I --max-time 10 "$T" 2>/dev/null)
if echo "$H" | grep -qi "connection: keep-alive"; then
  emit "{\"title\":\"Keep-alive connections enabled\",\"severity\":\"info\",\"description\":\"Keep-alive is enabled. Slowloris-style attacks may be effective if no timeout is configured.\",\"remediation\":\"Set reasonable keep-alive timeouts (5-15s).\",\"cweId\":\"CWE-400\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
