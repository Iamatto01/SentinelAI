#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        GraphQL Introspection & Depth Attack
# Description: Tests GraphQL introspection query and schema dump
# Severity:    MEDIUM
# Category:    Information & Sensitive Data Disclosure
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: GraphQL Introspection & Depth Attack\033[0m"
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
GQL_PATHS="graphql graphql/ api/graphql api/v1/graphql query graph"
for G in $GQL_PATHS; do
  R=$(curl -s -X POST -H "Content-Type: application/json" -d '{"query":"{ __schema { types { name } } }"}' --max-time 10 "$T/$G" 2>/dev/null)
  if echo "$R" | grep -q "__schema"; then
    NTYPES=$(echo "$R" | grep -o '"name"' | wc -l)
    emit "{\"title\":\"GraphQL introspection enabled: /$G\",\"severity\":\"medium\",\"description\":\"GraphQL introspection is enabled at /$G (~$NTYPES types). Full schema can be dumped — reveals all queries, mutations, and data models.\",\"remediation\":\"Disable introspection in production. Use depth limiting and cost analysis.\",\"cweId\":\"CWE-200\",\"owaspCategory\":\"A01:2025-Broken Access Control\"}"
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
