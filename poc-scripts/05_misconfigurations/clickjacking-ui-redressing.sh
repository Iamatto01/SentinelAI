#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Clickjacking (UI Redressing)
# Description: Tests if the site can be embedded in an iframe
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Clickjacking (UI Redressing)\033[0m"
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
H=$(curl -s -I --max-time 10 "$T" 2>/dev/null)
XFO=$(echo "$H" | grep -i "x-frame-options" | tr -d '\r')
CSP=$(echo "$H" | grep -i "content-security-policy" | grep -i "frame-ancestors" | tr -d '\r')
if [ -z "$XFO" ] && [ -z "$CSP" ]; then
  emit "{\"title\":\"Clickjacking — no frame protection\",\"severity\":\"medium\",\"description\":\"Neither X-Frame-Options nor CSP frame-ancestors is set. Site can be embedded in iframes — clickjacking attacks possible.\",\"remediation\":\"Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.\",\"cweId\":\"CWE-1021\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
