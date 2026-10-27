#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        API Documentation Exposure
# Description: Detects unprotected Swagger/OpenAPI/GraphiQL docs
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: API Documentation Exposure\033[0m"
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
PATHS="swagger swagger-ui swagger-ui/ swagger-ui.html swagger-ui/index.html swagger/index.html api-docs api-docs/swagger.json api/swagger.json v2/api-docs v3/api-docs openapi.json api/openapi.json docs api/docs graphiql graphql-playground redoc rapidoc api-reference"
for P in $PATHS; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ]; then
    BODY=$(curl -s --max-time 8 "$T/$P" 2>/dev/null | head -c 1000)
    if echo "$BODY" | grep -qi "swagger\|openapi\|graphiql\|api-docs\|paths.*get"; then
      emit "{\"title\":\"API documentation exposed: /$P\",\"severity\":\"medium\",\"description\":\"Interactive API documentation at /$P is publicly accessible. Reveals all endpoints, parameters, and data models.\",\"remediation\":\"Restrict API docs to authenticated users or remove from production.\",\"cweId\":\"CWE-200\",\"owaspCategory\":\"A01:2025-Broken Access Control\"}"
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
