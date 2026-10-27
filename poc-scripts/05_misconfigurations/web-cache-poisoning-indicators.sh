#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Web Cache Poisoning Indicators
# Description: Tests unkeyed headers for cache poisoning potential
# Severity:    HIGH
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Web Cache Poisoning Indicators\033[0m"
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
# check if response is cached and reflects unkeyed headers
H1=$(curl -s -I -H "X-Forwarded-Scheme: nothttp" --max-time 10 "$T" 2>/dev/null)
if echo "$H1" | grep -qi "x-cache.*hit\|cf-cache-status.*HIT\|age: [1-9]"; then
  # response is cached — check for unkeyed input reflection
  R=$(curl -s -H "X-Forwarded-Host: cache-poison-test.com" --max-time 10 "$T" 2>/dev/null | head -c 3000)
  if echo "$R" | grep -q "cache-poison-test"; then
    emit "{\"title\":\"Web cache poisoning via X-Forwarded-Host\",\"severity\":\"critical\",\"description\":\"X-Forwarded-Host is reflected in cached responses. Attacker can poison the cache to serve malicious content to all users.\",\"remediation\":\"Strip unkeyed headers at cache layer. Vary cache key on all relevant headers.\",\"cweId\":\"CWE-444\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
fi
# fat GET / cache key injection
R2=$(curl -s -H "X-Original-URL: /admin" --max-time 10 "$T/" 2>/dev/null | head -c 2000)
if echo "$R2" | grep -qi "admin.*dashboard\|administrator"; then
  emit "{\"title\":\"X-Original-URL override — hidden admin access\",\"severity\":\"high\",\"description\":\"X-Original-URL header overrides routing. Access control bypass possible to reach /admin.\",\"remediation\":\"Do not trust X-Original-URL or X-Rewrite-URL headers.\",\"cweId\":\"CWE-436\",\"owaspCategory\":\"A01:2025-Broken Access Control\"}"
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
