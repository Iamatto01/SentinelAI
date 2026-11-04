#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Exposed .hg Repository (Mercurial)
# Description: Checks for readable .hg directory
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Exposed .hg Repository (Mercurial)\033[0m"
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
HG_URL="$T/.hg/store"
R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$HG_URL")
if [ "$R" = "200" ] || [ "$R" = "403" ]; then
  BODY=$(curl -s --max-time 10 "$HG_URL" | head -c 400)
  BODY_JSON=$(printf '%s' "$BODY" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')
  emit "{\"title\":\"Exposed .hg repository\",\"severity\":\"high\",\"description\":\"Mercurial metadata found at /.hg/. Repository contents may be recoverable.\",\"remediation\":\"Block access to .hg directory.\",\"cweId\":\"CWE-548\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\",\"evidence\":{\"url\":\"$HG_URL\",\"method\":\"GET\",\"status\":$R,\"bodyPreview\":$BODY_JSON,\"contentLength\":${#BODY}}}"
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
