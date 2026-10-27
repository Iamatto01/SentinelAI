#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        CORS Preflight & Method Abuse
# Description: Tests preflight handling and method allowlist enforcement
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: CORS Preflight & Method Abuse\033[0m"
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
# preflight with custom method
R=$(curl -s -o /dev/null -w "%{http_code}" -X OPTIONS -H "Origin: https://evil.example.com" -H "Access-Control-Request-Method: DELETE" --max-time 10 "$T/api" 2>/dev/null)
if [ "$R" = "204" ] || [ "$R" = "200" ]; then
  H=$(curl -s -I -X OPTIONS -H "Origin: https://evil.example.com" -H "Access-Control-Request-Method: DELETE" --max-time 10 "$T/api" 2>/dev/null)
  ACAOM=$(echo "$H" | grep -i "access-control-allow-methods" | tr -d '\r')
  if echo "$ACAO M" | grep -qi "delete\|\*"; then
    emit "{\"title\":\"CORS allows DELETE from any origin\",\"severity\":\"high\",\"description\":\"Preflight response allows DELETE method for arbitrary origins. Cross-origin data deletion possible.\",\"remediation\":\"Restrict CORS to specific trusted origins. Whitelist safe methods only.\",\"cweId\":\"CWE-942\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
fi
# preflight with custom headers
R2=$(curl -s -I -X OPTIONS -H "Origin: https://evil.example.com" -H "Access-Control-Request-Method: POST" -H "Access-Control-Request-Headers: X-Custom-Header,Authorization" --max-time 10 "$T/api" 2>/dev/null)
if echo "$R2" | grep -qi "access-control-allow-headers.*authorization"; then
  if echo "$R2" | grep -qi "access-control-allow-origin.*evil"; then
    emit "{\"title\":\"CORS reflects arbitrary origin with Authorization header\",\"severity\":\"high\",\"description\":\"Preflight allows Authorization header from evil.example.com. Authenticated cross-origin requests possible.\",\"remediation\":\"Whitelist origins strictly. Never reflect arbitrary Origin headers.\",\"cweId\":\"CWE-942\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
