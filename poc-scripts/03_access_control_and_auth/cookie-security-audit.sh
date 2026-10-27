#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Cookie Security Audit
# Description: Checks cookies for Secure, HttpOnly, SameSite flags
# Severity:    MEDIUM
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Cookie Security Audit\033[0m"
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
COOKIES=$(curl -s -I --max-time 10 "$T" 2>/dev/null | grep -i "set-cookie")
if [ -z "$COOKIES" ]; then
  exit 0
fi
echo "$COOKIES" | while IFS= read -r line; do
  CNAME=$(echo "$line" | sed 's/[Ss]et-[Cc]ookie:\s*//' | cut -d= -f1 | tr -d ' ')
  HAS_SECURE=$(echo "$line" | grep -qi "secure" && echo "yes" || echo "no")
  HAS_HTTPONLY=$(echo "$line" | grep -qi "httponly" && echo "yes" || echo "no")
  HAS_SAMESITE=$(echo "$line" | grep -qi "samesite" && echo "yes" || echo "no")
  if [ "$HAS_SECURE" = "no" ]; then
    emit "{\"title\":\"Cookie without Secure flag: $CNAME\",\"severity\":\"medium\",\"description\":\"Cookie $CNAME is set without the Secure flag — can be transmitted over unencrypted HTTP.\",\"remediation\":\"Add Secure flag to all cookies.\",\"cweId\":\"CWE-614\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
  if [ "$HAS_HTTPONLY" = "no" ]; then
    emit "{\"title\":\"Cookie without HttpOnly flag: $CNAME\",\"severity\":\"medium\",\"description\":\"Cookie $CNAME is accessible via JavaScript — XSS can steal session tokens.\",\"remediation\":\"Add HttpOnly flag to session cookies.\",\"cweId\":\"CWE-1004\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
  if [ "$HAS_SAMESITE" = "no" ]; then
    emit "{\"title\":\"Cookie without SameSite flag: $CNAME\",\"severity\":\"low\",\"description\":\"Cookie $CNAME lacks SameSite attribute — CSRF attacks possible.\",\"remediation\":\"Add SameSite=Lax or Strict to cookies.\",\"cweId\":\"CWE-1275\",\"owaspCategory\":\"A01:2025-Broken Access Control\"}"
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
