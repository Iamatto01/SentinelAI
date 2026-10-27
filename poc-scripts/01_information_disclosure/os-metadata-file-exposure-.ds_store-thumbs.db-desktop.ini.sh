#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        OS Metadata File Exposure (.DS_Store, Thumbs.db, desktop.ini)
# Description: Detects macOS/Windows metadata files that leak directory structure
# Severity:    MEDIUM
# Category:    Information & Sensitive Data Disclosure
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: OS Metadata File Exposure (.DS_Store, Thumbs.db, desktop.ini)\033[0m"
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
PATHS=".DS_Store Thumbs.db desktop.ini .DS_Store? desktop.ini? __MACOSX/ ._.DS_Store ~$Thumbs.db"
for P in $PATHS; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ]; then
    SZ=$(curl -s --max-time 8 "$T/$P" 2>/dev/null | wc -c)
    if [ "$SZ" -gt 100 ]; then
      emit "{\"title\":\"OS metadata file exposed: /$P\",\"severity\":\"medium\",\"description\":\"OS metadata file /$P is downloadable (${SZ} bytes). .DS_Store files reveal complete directory structure and hidden files.\",\"remediation\":\"Remove OS metadata files from web root. Add to deployment ignore lists.\",\"cweId\":\"CWE-548\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
