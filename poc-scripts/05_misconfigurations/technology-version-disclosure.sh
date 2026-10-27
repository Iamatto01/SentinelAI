#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Technology Version Disclosure
# Description: Checks headers and pages for version numbers that aid targeted attacks
# Severity:    LOW
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Technology Version Disclosure\033[0m"
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
# Server header
SRV=$(echo "$H" | grep -i "^server:" | tr -d '\r' | sed 's/[Ss]erver: //')
if [ -n "$SRV" ] && echo "$SRV" | grep -qE "[0-9]+\.[0-9]+"; then
  emit "{\"title\":\"Server version disclosed: $SRV\",\"severity\":\"low\",\"description\":\"Server header reveals version: $SRV. Attackers can target known CVEs for this exact version.\",\"remediation\":\"Set ServerTokens Prod (Apache) or server_tokens off (nginx).\",\"cweId\":\"CWE-200\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi
# X-Powered-By
XPB=$(echo "$H" | grep -i "x-powered-by" | tr -d '\r' | sed 's/.*: //')
if [ -n "$XPB" ]; then
  emit "{\"title\":\"X-Powered-By header exposed: $XPB\",\"severity\":\"low\",\"description\":\"X-Powered-By reveals technology: $XPB. Aids targeted attacks.\",\"remediation\":\"Remove X-Powered-By header (expose_php=Off for PHP).\",\"cweId\":\"CWE-200\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi
# Meta generator tags
BODY=$(curl -s --max-time 10 "$T" 2>/dev/null | head -c 10000)
GEN=$(echo "$BODY" | grep -o '<meta name="generator" content="[^"]*"' | cut -d'"' -f4 | head -1)
if [ -n "$GEN" ]; then
  emit "{\"title\":\"CMS generator tag exposed: $GEN\",\"severity\":\"low\",\"description\":\"Meta generator tag reveals CMS and version: $GEN.\",\"remediation\":\"Remove generator meta tag from templates.\",\"cweId\":\"CWE-200\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
