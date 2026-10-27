#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        API Endpoint Discovery (20 paths)
# Description: Discovers exposed API endpoints — REST, GraphQL, Swagger, gRPC
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: API Endpoint Discovery (20 paths)\033[0m"
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
PATHS="api api/v1 api/v2 api/v3 api/v1/users api/v1/user api/v1/auth api/v1/login api/v1/me api/v1/config api/v1/settings api/v1/admin api/v1/orders api/v1/products api/v1/data api/v1/status api/v1/health api/v1/metrics api/v1/version api/v1/info graphql graphiql swagger swagger.json swagger-ui swagger/index.html api-docs v1/swagger.json openapi.json api/openapi.json"
for P in $PATHS; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 6 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ]; then
    CT=$(curl -s -I --max-time 6 "$T/$P" 2>/dev/null | grep -i content-type | tr -d '\r' | sed 's/.*: //')
    if echo "$CT" | grep -qi "json\|html"; then
      SEV="info"
      case "$P" in graphql|graphiql|swagger*|api-docs|openapi*) SEV="medium";; esac
      emit "{\"title\":\"API endpoint discovered: /$P\",\"severity\":\"$SEV\",\"description\":\"API endpoint /$P returns HTTP 200 ($CT). Exposed API surface increases attack surface.\",\"remediation\":\"Ensure API endpoints have proper authentication and rate limiting.\",\"cweId\":\"CWE-200\",\"owaspCategory\":\"A01:2025-Broken Access Control\"}"
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
