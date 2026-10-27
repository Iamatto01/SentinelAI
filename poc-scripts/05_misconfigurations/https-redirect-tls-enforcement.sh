#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        HTTPS Redirect & TLS Enforcement
# Description: Verifies HTTP→HTTPS redirect and HSTS preload readiness
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: HTTPS Redirect & TLS Enforcement\033[0m"
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
HOST=$(echo "$T" | sed 's|https\?://||' | cut -d/ -f1)
# check HTTP redirect
R=$(curl -s -o /dev/null -w "%{http_code}|%{redirect_url}" --max-time 10 "http://$HOST" 2>/dev/null)
CODE=$(echo "$R" | cut -d'|' -f1)
LOC=$(echo "$R" | cut -d'|' -f2)
if [ "$CODE" = "200" ]; then
  emit "{\"title\":\"No HTTP to HTTPS redirect\",\"severity\":\"medium\",\"description\":\"http://$HOST serves content directly (HTTP 200) without redirecting to HTTPS. Traffic can be intercepted.\",\"remediation\":\"Add 301 redirect from HTTP to HTTPS. Enable HSTS.\",\"cweId\":\"CWE-319\",\"owaspCategory\":\"A02:2025-Cryptographic Failures\"}"
elif [ "$CODE" = "301" ] || [ "$CODE" = "308" ]; then
  if ! echo "$LOC" | grep -q "^https"; then
    emit "{\"title\":\"HTTP redirects to non-HTTPS URL\",\"severity\":\"medium\",\"description\":\"HTTP redirects to $LOC which is not HTTPS.\",\"remediation\":\"Redirect to the HTTPS version of the same URL.\",\"cweId\":\"CWE-319\",\"owaspCategory\":\"A02:2025-Cryptographic Failures\"}"
  fi
fi
# HSTS check
H=$(curl -s -I --max-time 10 "https://$HOST" 2>/dev/null)
HSTS=$(echo "$H" | grep -i "strict-transport-security" | tr -d '\r')
if [ -n "$HSTS" ]; then
  if ! echo "$HSTS" | grep -q "includeSubDomains"; then
    emit "{\"title\":\"HSTS missing includeSubDomains\",\"severity\":\"low\",\"description\":\"HSTS is set but without includeSubDomains directive. Subdomains remain vulnerable to downgrade.\",\"remediation\":\"Add includeSubDomains to HSTS header.\",\"cweId\":\"CWE-319\",\"owaspCategory\":\"A02:2025-Cryptographic Failures\"}"
  fi
  if ! echo "$HSTS" | grep -q "preload"; then
    emit "{\"title\":\"HSTS missing preload directive\",\"severity\":\"info\",\"description\":\"HSTS lacks preload directive — domain not eligible for browser preload list.\",\"remediation\":\"Add preload after verifying all subdomains support HTTPS.\",\"cweId\":\"CWE-319\",\"owaspCategory\":\"A02:2025-Cryptographic Failures\"}"
  fi
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
