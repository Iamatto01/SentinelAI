#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        API Gateway & Microservice Discovery
# Description: Maps API gateways, service meshes, and internal routing
# Severity:    MEDIUM
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: API Gateway & Microservice Discovery\033[0m"
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
# common gateway paths
PATHS="gateway api-gateway api/v1 api/v2 api/v3 v1 v2 graphql rest rpc grpc-web .well-known/api openapi.json swagger.json api-docs"
for P in $PATHS; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ]; then
    CT=$(curl -s -I --max-time 8 "$T/$P" 2>/dev/null | grep -i content-type | tr -d '\r')
    if echo "$CT" | grep -qi "json\|yaml"; then
      BODY=$(curl -s --max-time 8 "$T/$P" 2>/dev/null | head -c 1000)
      if echo "$BODY" | grep -qi "openapi\|swagger\|paths\|servers"; then
        emit "{\"title\":\"API specification exposed: /$P\",\"severity\":\"high\",\"description\":\"OpenAPI/Swagger specification is accessible at /$P. Full API surface — endpoints, parameters, schemas — disclosed.\",\"remediation\":\"Remove API docs from production or require authentication.\",\"cweId\":\"CWE-200\",\"owaspCategory\":\"A01:2025-Broken Access Control\"}"
      fi
    fi
  fi
done
# service mesh headers
H=$(curl -s -I --max-time 10 "$T/api" 2>/dev/null)
if echo "$H" | grep -qi "x-envoy\|x-istio\|x-kong\|x-traefik"; then
  GATEWAY=$(echo "$H" | grep -ioE "x-(envoy|istio|kong|traefik)[^\r]*" | head -1)
  emit "{\"title\":\"API gateway detected: $GATEWAY\",\"severity\":\"info\",\"description\":\"Response headers reveal API gateway technology ($GATEWAY). Gateway-specific bypasses may apply.\",\"remediation\":\"Strip internal headers at gateway egress.\",\"cweId\":\"CWE-200\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
