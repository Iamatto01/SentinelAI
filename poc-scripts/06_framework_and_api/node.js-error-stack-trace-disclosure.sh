#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Node.js Error Stack Trace Disclosure
# Description: Probes for stack traces revealing file paths and framework internals
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Node.js Error Stack Trace Disclosure\033[0m"
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
# trigger errors via malformed requests
RESP=$(curl -s --max-time 10 "$T/%00" 2>/dev/null | head -c 3000)
RESP2=$(curl -s -X POST -H "Content-Type: application/json" -d '{invalid' --max-time 10 "$T/" 2>/dev/null | head -c 3000)
RESP3=$(curl -s --max-time 10 "$T/undefined/null" 2>/dev/null | head -c 3000)
ALL="$RESP $RESP2 $RESP3"
if echo "$ALL" | grep -q "at .*\\.js:"; then
  FRAMEWORK="Node.js"
  echo "$ALL" | grep -q "node_modules" && FRAMEWORK="Node.js (node_modules paths visible)"
  emit "{\"title\":\"Stack trace disclosure ($FRAMEWORK)\",\"severity\":\"medium\",\"description\":\"Error responses contain JavaScript stack traces with file paths. Reveals internal structure, framework, and library versions.\",\"remediation\":\"Disable stack traces in production. Return generic error pages.\",\"cweId\":\"CWE-209\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
