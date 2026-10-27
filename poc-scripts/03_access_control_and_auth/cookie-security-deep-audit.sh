#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Cookie Security Deep Audit
# Description: Analyzes all cookies for flags, scope, and session patterns
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Cookie Security Deep Audit\033[0m"
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
# collect cookies from multiple pages
COOKIES=""
for P in "" "login" "dashboard" "api/user"; do
  C=$(curl -s -I -L --max-time 10 "$T/$P" 2>/dev/null | grep -i "set-cookie" | tr -d '\r')
  COOKIES="$COOKIES\n$C"
done
UNIQ=$(echo -e "$COOKIES" | sort -u | grep -v '^$')
echo "$UNIQ" | while IFS= read -r LINE; do
  CNAME=$(echo "$LINE" | sed 's/.*[Ss]et-[Cc]ookie: //' | cut -d= -f1)
  if echo "$LINE" | grep -qi "httponly"; then HTTPOK=1; else HTTPOK=0; fi
  if echo "$LINE" | grep -qi "secure"; then SECOK=1; else SECOK=0; fi
  if echo "$LINE" | grep -qi "samesite"; then SSOK=1; else SSOK=0; fi
  ISSID=$(echo "$CNAME" | grep -qi "sess\|sid\|auth\|token\|jwt" && echo 1 || echo 0)
  if [ "$HTTPOK" = "0" ] && [ "$ISSID" = "1" ]; then
    emit "{\"title\":\"Session cookie missing HttpOnly: $CNAME\",\"severity\":\"medium\",\"description\":\"Cookie $CNAME appears to be session-related but lacks HttpOnly flag. JavaScript can read it — XSS steals sessions.\",\"remediation\":\"Add HttpOnly flag to all session cookies.\",\"cweId\":\"CWE-1004\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
  if [ "$SECOK" = "0" ] && [ "$ISSID" = "1" ]; then
    emit "{\"title\":\"Session cookie missing Secure flag: $CNAME\",\"severity\":\"medium\",\"description\":\"Cookie $CNAME lacks Secure flag — transmitted over HTTP if available.\",\"remediation\":\"Add Secure flag. Enforce HTTPS-only.\",\"cweId\":\"CWE-614\",\"owaspCategory\":\"A02:2025-Cryptographic Failures\"}"
  fi
  if [ "$SSOK" = "0" ] && [ "$ISSID" = "1" ]; then
    emit "{\"title\":\"Session cookie missing SameSite: $CNAME\",\"severity\":\"low\",\"description\":\"Cookie $CNAME lacks SameSite attribute — CSRF attacks easier.\",\"remediation\":\"Add SameSite=Lax or Strict.\",\"cweId\":\"CWE-352\",\"owaspCategory\":\"A01:2025-Broken Access Control\"}"
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
