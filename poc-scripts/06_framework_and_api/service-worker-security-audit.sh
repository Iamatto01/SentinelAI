#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Service Worker Security Audit
# Description: Checks for exposed service workers and scope issues
# Severity:    MEDIUM
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Service Worker Security Audit\033[0m"
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
# find service worker registration
BODY=$(curl -s -L --max-time 15 "$T" 2>/dev/null)
SW=$(echo "$BODY" | grep -oE 'serviceWorker\.register\(["\'][^"\']+' | cut -d"'" -f2 | cut -d'"' -f2 | head -1)
if [ -z "$SW" ]; then
  SW=$(echo "$BODY" | grep -oE 'navigator\.serviceWorker[^;]*["\']([^"\']+)' | grep -oE '/[a-zA-Z0-9._/-]+\.js' | head -1)
fi
if [ -n "$SW" ]; then
  # fetch the SW file
  SWURL="$T$SW"
  if ! echo "$SW" | grep -q "^http"; then SWURL="$T/$SW"; fi
  SWBODY=$(curl -s --max-time 10 "$SWURL" 2>/dev/null | head -c 5000)
  if [ -n "$SWBODY" ]; then
    # check for broad scope
    if echo "$SWBODY" | grep -qi "importScripts"; then
      IMPORTS=$(echo "$SWBODY" | grep -oE "importScripts\(['\"][^'\"]+" | cut -d"'" -f2 | cut -d'"' -f2 | head -3)
      emit "{\"title\":\"Service worker imports external scripts\",\"severity\":\"medium\",\"description\":\"Service worker at $SW imports external scripts ($IMPORTS). Compromised import source = persistent XSS on all pages.\",\"remediation\":\"Use SRI hashes on imported scripts. Self-host all SW dependencies.\",\"cweId\":\"CWE-829\",\"owaspCategory\":\"A08:2025-Software and Data Integrity Failures\"}"
    fi
    # check for fetch handler without origin check
    if echo "$SWBODY" | grep -q "addEventListener.*fetch" && ! echo "$SWBODY" | grep -q "self\.origin\|location\.origin\|new URL.*origin"; then
      emit "{\"title\":\"Service worker fetch handler may lack origin validation\",\"severity\":\"low\",\"description\":\"Service worker registers fetch handler without visible origin checks — may intercept/proxy cross-origin requests.\",\"remediation\":\"Validate request origin in fetch handler. Only handle same-origin requests.\",\"cweId\":\"CWE-346\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
    fi
  fi
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
