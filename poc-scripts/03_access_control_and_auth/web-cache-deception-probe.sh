#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Web Cache Deception Probe
# Description: Tests for cacheable authenticated pages with extension suffixes
# Severity:    HIGH
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Web Cache Deception Probe\033[0m"
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
# try appending extensions to authenticated pages
PATHS="account/settings account/profile user/profile myaccount dashboard"
for P in $PATHS; do
  for EXT in ".css" ".js" ".png" ".ico"; do
    R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$P$EXT" 2>/dev/null)
    if [ "$R" = "200" ]; then
      CT=$(curl -s -I --max-time 8 "$T/$P$EXT" 2>/dev/null | grep -i "content-type\|cache-control" | tr -d '\r')
      if echo "$CT" | grep -qi "text/html" && ! echo "$CT" | grep -qi "no-store\|private"; then
        emit "{\"title\":\"Web cache deception possible: /$P$EXT\",\"severity\":\"high\",\"description\":\"Authenticated page /$P responds to extension suffix /$P$EXT with HTML content and cacheable headers. CDN may cache and serve to unauthenticated users.\",\"remediation\":\"Cache only static extensions. Set Cache-Control: no-store on authenticated pages.\",\"cweId\":\"CWE-524\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
      fi
    fi
  done
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
