#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        TLS/SSL Security Audit
# Description: Checks for weak protocols, expired certs, and mixed content
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: TLS/SSL Security Audit\033[0m"
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
# SSLv3/TLS1.0 check
if command -v openssl >/dev/null; then
  R1=$(echo | openssl s_client -connect "$HOST:443" -ssl3 2>&1 | grep -c "BEGIN CERT")
  if [ "$R1" -gt 0 ]; then
    emit "{\"title\":\"SSLv3 enabled\",\"severity\":\"high\",\"description\":\"Server accepts SSLv3 connections — POODLE attack (CVE-2014-3566) possible.\",\"remediation\":\"Disable SSLv3. Minimum TLS 1.2.\",\"cweId\":\"CWE-327\",\"owaspCategory\":\"A02:2025-Cryptographic Failures\"}"
  fi
  R2=$(echo | openssl s_client -connect "$HOST:443" -tls1 2>&1 | grep -c "BEGIN CERT")
  if [ "$R2" -gt 0 ]; then
    emit "{\"title\":\"TLS 1.0 enabled\",\"severity\":\"medium\",\"description\":\"Server accepts TLS 1.0 — deprecated protocol with known weaknesses.\",\"remediation\":\"Disable TLS 1.0 and 1.1. Minimum TLS 1.2.\",\"cweId\":\"CWE-327\",\"owaspCategory\":\"A02:2025-Cryptographic Failures\"}"
  fi
  # cert expiry
  EXP=$(echo | openssl s_client -connect "$HOST:443" -servername "$HOST" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
  if [ -n "$EXP" ]; then
    EXP_TS=$(date -d "$EXP" +%s 2>/dev/null)
    NOW_TS=$(date +%s)
    if [ -n "$EXP_TS" ] && [ $EXP_TS -lt $((NOW_TS + 2592000)) ]; then
      emit "{\"title\":\"TLS certificate expiring soon: $EXP\",\"severity\":\"medium\",\"description\":\"TLS certificate expires on $EXP (within 30 days).\",\"remediation\":\"Renew certificate before expiry. Set up auto-renewal.\",\"cweId\":\"CWE-298\",\"owaspCategory\":\"A02:2025-Cryptographic Failures\"}"
    fi
  fi
fi
# Mixed content
BODY=$(curl -s --max-time 10 "$T" 2>/dev/null | head -c 20000)
if echo "$T" | grep -q "^https"; then
  HTTP_LINKS=$(echo "$BODY" | grep -o 'http://[^"'''  ]*' | grep -v 'localhost\|127.0.0.1\|schemas\|w3.org\|xmlns' | head -3)
  if [ -n "$HTTP_LINKS" ]; then
    emit "{\"title\":\"Mixed content on HTTPS page\",\"severity\":\"medium\",\"description\":\"HTTPS page loads resources over HTTP: $HTTP_LINKS. Active mixed content enables MITM attacks.\",\"remediation\":\"Load all resources via HTTPS. Use upgrade-insecure-requests CSP directive.\",\"cweId\":\"CWE-311\",\"owaspCategory\":\"A02:2025-Cryptographic Failures\"}"
  fi
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
