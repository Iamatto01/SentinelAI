#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        PWA Manifest & Metadata Exposure
# Description: Extracts tech stack and internal URLs from manifest files
# Severity:    INFO
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: PWA Manifest & Metadata Exposure\033[0m"
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
# manifest.json
MANIFEST=$(curl -s --max-time 10 "$T/manifest.json" 2>/dev/null | head -c 3000)
if [ -n "$MANIFEST" ] && echo "$MANIFEST" | grep -q "name\|icons"; then
  # extract internal URLs
  URLS=$(echo "$MANIFEST" | grep -oE 'https?://[^"\s]+' | grep -v "$T" | head -5)
  if [ -n "$URLS" ]; then
    emit "{\"title\":\"Manifest reveals external URLs\",\"severity\":\"info\",\"description\":\"PWA manifest references external URLs: $URLS. Maps third-party dependencies and potential API endpoints.\",\"remediation\":\"Informational — review external dependencies.\",\"cweId\":\"CWE-200\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
fi
# humans.txt / security.txt
for F in "humans.txt" ".well-known/security.txt" "security.txt"; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$F" 2>/dev/null)
  if [ "$R" = "200" ]; then
    BODY=$(curl -s --max-time 8 "$T/$F" 2>/dev/null | head -c 1000)
    EMAILS=$(echo "$BODY" | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | head -3)
    if [ -n "$EMAILS" ]; then
      emit "{\"title\":\"Contact info in /$F\",\"severity\":\"info\",\"description\":\"File /$F exposes email addresses: $EMAILS. Useful for social engineering assessment.\",\"remediation\":\"Use role-based emails (security@) not personal addresses.\",\"cweId\":\"CWE-200\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
