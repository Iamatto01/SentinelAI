#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Security Headers Audit (8 headers)
# Description: Checks for 8 critical security headers on the main page
# Severity:    LOW
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Security Headers Audit (8 headers)\033[0m"
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
H=$(curl -s -I --max-time 10 "$T" 2>/dev/null)
check() {
  echo "$H" | grep -qi "$1" || emit "{\"title\":\"Missing security header: $1\",\"severity\":\"$2\",\"description\":\"$3\",\"remediation\":\"$6\",\"cweId\":\"$4\",\"owaspCategory\":\"$5\"}"
}
check "strict-transport-security" "high" "HSTS header missing — protocol downgrade and session hijacking possible" "CWE-319" "A05:2025-Security Misconfiguration" "Enable HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains"
check "content-security-policy" "medium" "CSP header missing — XSS attack surface greatly increased" "CWE-693" "A05:2025-Security Misconfiguration" "Implement Content-Security-Policy with restrictive default-src"
check "x-frame-options" "medium" "X-Frame-Options missing — clickjacking attacks possible" "CWE-1021" "A05:2025-Security Misconfiguration" "Add X-Frame-Options: DENY or SAMEORIGIN"
check "x-content-type-options" "low" "X-Content-Type-Options missing — MIME sniffing attacks possible" "CWE-430" "A05:2025-Security Misconfiguration" "Add X-Content-Type-Options: nosniff"
check "referrer-policy" "low" "Referrer-Policy missing — URL leakage to third parties" "CWE-200" "A01:2025-Broken Access Control" "Add Referrer-Policy: strict-origin-when-cross-origin"
check "permissions-policy" "low" "Permissions-Policy missing — browser features not restricted" "CWE-1021" "A05:2025-Security Misconfiguration" "Add Permissions-Policy to restrict camera, microphone, geolocation"
check "cross-origin-opener-policy" "low" "COOP header missing — cross-origin window attacks possible" "CWE-1021" "A05:2025-Security Misconfiguration" "Add Cross-Origin-Opener-Policy: same-origin"
check "cross-origin-resource-policy" "low" "CORP header missing — cross-origin resource attacks possible" "CWE-1021" "A05:2025-Security Misconfiguration" "Add Cross-Origin-Resource-Policy: same-origin"

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
