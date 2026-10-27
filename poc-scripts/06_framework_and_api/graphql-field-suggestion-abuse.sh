#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        GraphQL Field Suggestion Abuse
# Description: Exploits GraphQL error suggestions for schema enumeration
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: GraphQL Field Suggestion Abuse\033[0m"
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
# test field suggestions
R=$(curl -s -X POST -H "Content-Type: application/json" -d '{"query":"{ user }"}' --max-time 10 "$T/graphql" 2>/dev/null | head -c 1000)
if echo "$R" | grep -qi "Did you mean"; then
  SUGGESTION=$(echo "$R" | grep -oE "Did you mean [^,]+\?" | head -1)
  emit "{\"title\":\"GraphQL field suggestions enabled\",\"severity\":\"medium\",\"description\":\"GraphQL error messages suggest field names ($SUGGESTION). Full schema enumeration possible without introspection.\",\"remediation\":\"Disable field suggestions in production. Return generic errors.\",\"cweId\":\"CWE-209\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi
# alias-based rate limit bypass check
R2=$(curl -s -X POST -H "Content-Type: application/json" -d '{"query":"{ a1: __typename a2: __typename a3: __typename a4: __typename a5: __typename a6: __typename a7: __typename a8: __typename a9: __typename a10: __typename }"}' --max-time 10 "$T/graphql" 2>/dev/null | head -c 500)
if echo "$R2" | grep -q "a10"; then
  emit "{\"title\":\"GraphQL aliasing allows batched queries\",\"severity\":\"low\",\"description\":\"GraphQL accepts 10+ aliases in single request — rate limit bypass and brute force via batching possible.\",\"remediation\":\"Limit query complexity and aliases per request.\",\"cweId\":\"CWE-770\",\"owaspCategory\":\"A04:2025-Insecure Design\"}"
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
