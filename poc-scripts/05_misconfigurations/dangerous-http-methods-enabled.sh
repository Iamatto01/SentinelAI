#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Dangerous HTTP Methods Enabled
# Description: Tests for TRACE, TRACK, PUT, DELETE, CONNECT methods
# Severity:    MEDIUM
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Dangerous HTTP Methods Enabled\033[0m"
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
# TRACE test (XST)
R=$(curl -s -o /dev/null -w "%{http_code}" -X TRACE --max-time 10 "$T" 2>/dev/null)
if [ "$R" = "200" ]; then
  emit "{\"title\":\"HTTP TRACE method enabled (XST)\",\"severity\":\"medium\",\"description\":\"TRACE method is enabled — Cross-Site Tracing attacks can steal HttpOnly cookies.\",\"remediation\":\"Disable TRACE method in web server configuration.\",\"cweId\":\"CWE-436\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi
# OPTIONS enumeration
ALLOWED=$(curl -s -I -X OPTIONS --max-time 10 "$T" 2>/dev/null | grep -i "^allow" | tr -d '\r')
if echo "$ALLOWED" | grep -qE "PUT|DELETE|CONNECT|PATCH"; then
  emit "{\"title\":\"Dangerous HTTP methods allowed: $ALLOWED\",\"severity\":\"medium\",\"description\":\"Server allows potentially dangerous HTTP methods. PUT allows file upload, DELETE allows resource removal.\",\"remediation\":\"Restrict allowed methods to GET, POST, HEAD unless others are required.\",\"cweId\":\"CWE-650\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
