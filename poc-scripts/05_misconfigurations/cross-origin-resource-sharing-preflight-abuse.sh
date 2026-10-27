#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Cross-Origin Resource Sharing Preflight Abuse
# Description: Deep CORS test — preflight method/header allowlist analysis
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Cross-Origin Resource Sharing Preflight Abuse\033[0m"
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
# test preflight with dangerous methods
H=$(curl -s -I -X OPTIONS -H "Origin: https://evil.com" -H "Access-Control-Request-Method: DELETE" -H "Access-Control-Request-Headers: authorization,content-type,x-custom" --max-time 10 "$T" 2>/dev/null)
ACAM=$(echo "$H" | grep -i "access-control-allow-methods" | tr -d '\r')
ACAH=$(echo "$H" | grep -i "access-control-allow-headers" | tr -d '\r')
ACAC=$(echo "$H" | grep -i "access-control-allow-credentials" | tr -d '\r')
if echo "$ACAM" | grep -qi "delete\|put\|patch" && echo "$ACAC" | grep -qi "true"; then
  emit "{\"title\":\"CORS allows dangerous methods with credentials\",\"severity\":\"high\",\"description\":\"Preflight allows $ACAM with credentials ($ACAC). Cross-origin state-changing requests possible from any origin.\",\"remediation\":\"Restrict CORS methods to what's needed. Never combine wildcard origins with credentials.\",\"cweId\":\"CWE-942\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi
if echo "$ACAH" | grep -qi "authorization" && echo "$ACAC" | grep -qi "true"; then
  emit "{\"title\":\"CORS allows Authorization header cross-origin\",\"severity\":\"high\",\"description\":\"Preflight allows Authorization header with credentials. Cross-origin authenticated API calls possible.\",\"remediation\":\"Restrict allowed headers. Whitelist specific origins only.\",\"cweId\":\"CWE-942\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
