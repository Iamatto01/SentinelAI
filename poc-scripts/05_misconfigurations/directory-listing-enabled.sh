#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Directory Listing Enabled
# Description: Checks common directories for index listing
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Directory Listing Enabled\033[0m"
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
DIRS="uploads upload images img assets static files docs doc downloads media data temp tmp backup backups css js"
for D in $DIRS; do
  BODY=$(curl -s --max-time 8 "$T/$D/" 2>/dev/null | head -c 2000)
  if echo "$BODY" | grep -qi "Index of /"; then
    emit "{\"title\":\"Directory listing enabled: /$D/\",\"severity\":\"medium\",\"description\":\"Directory listing is enabled at /$D/ — all files are enumerable. May expose sensitive files, backups, or uploads.\",\"remediation\":\"Disable directory listing (Options -Indexes in Apache, autoindex off in nginx).\",\"cweId\":\"CWE-548\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
