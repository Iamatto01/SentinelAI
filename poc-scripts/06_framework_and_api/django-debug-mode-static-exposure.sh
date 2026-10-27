#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Django Debug Mode & Static Exposure
# Description: Detects DEBUG=True, exposed settings, collectstatic misconfig
# Severity:    HIGH
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Django Debug Mode & Static Exposure\033[0m"
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
# Django debug page (404 with debug info)
R404=$(curl -s --max-time 10 "$T/nonexistent-page-xyz" 2>/dev/null | head -c 5000)
if echo "$R404" | grep -q "DJANGO\|Using the URLconf\|tried these"; then
  emit "{\"title\":\"Django DEBUG mode enabled\",\"severity\":\"critical\",\"description\":\"Django 404 page reveals URL configuration and all registered routes. DEBUG=True in production exposes settings, SQL queries, and stack traces.\",\"remediation\":\"Set DEBUG=False in production settings.\",\"cweId\":\"CWE-489\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi
# exposed static root
for P in "static/static" "staticfiles" "static/admin" "media/" "static/debug_toolbar"; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ] || [ "$R" = "403" ]; then
    BODY=$(curl -s --max-time 8 "$T/$P/" 2>/dev/null | head -c 300)
    if echo "$BODY" | grep -qi "index of\|directory"; then
      emit "{\"title\":\"Django static/media directory listing: /$P\",\"severity\":\"low\",\"description\":\"Django static or media directory is listable.\",\"remediation\":\"Disable directory listing on static/media paths.\",\"cweId\":\"CWE-548\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
