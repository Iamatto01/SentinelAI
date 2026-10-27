#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        CORS Wildcard Misconfiguration
# Description: Tests for Access-Control-Allow-Origin: * and credential reflection
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: CORS Wildcard Misconfiguration\033[0m"
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
# Test 1: wildcard origin
H1=$(curl -s -I -H "Origin: https://evil.com" --max-time 10 "$T" 2>/dev/null)
ACAO=$(echo "$H1" | grep -i "access-control-allow-origin" | tr -d '\r' | sed 's/.*: //')
ACAC=$(echo "$H1" | grep -i "access-control-allow-credentials" | tr -d '\r' | sed 's/.*: //')
if [ "$ACAO" = "*" ]; then
  emit "{\"title\":\"CORS wildcard origin allowed\",\"severity\":\"medium\",\"description\":\"Access-Control-Allow-Origin: * is set. Any website can read responses cross-origin.\",\"remediation\":\"Restrict CORS to specific trusted origins.\",\"cweId\":\"CWE-942\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi
if [ "$ACAO" = "https://evil.com" ] && echo "$ACAC" | grep -qi "true"; then
  emit "{\"title\":\"CORS arbitrary origin reflection with credentials\",\"severity\":\"critical\",\"description\":\"Server reflects arbitrary Origin AND allows credentials. Any website can make authenticated cross-origin requests and read responses — full account takeover via CSRF-style attack.\",\"remediation\":\"Whitelist specific origins. Never reflect arbitrary Origin with Allow-Credentials: true.\",\"cweId\":\"CWE-942\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi
if [ "$ACAO" = "https://evil.com" ]; then
  emit "{\"title\":\"CORS arbitrary origin reflection\",\"severity\":\"high\",\"description\":\"Server reflects arbitrary Origin in Access-Control-Allow-Origin. Cross-origin data reads possible.\",\"remediation\":\"Whitelist specific origins only.\",\"cweId\":\"CWE-942\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
