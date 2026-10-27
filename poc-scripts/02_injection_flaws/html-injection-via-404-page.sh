#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        HTML Injection via 404 Page
# Description: Tests if 404 pages reflect user input without encoding
# Severity:    MEDIUM
# Category:    Injection Flaws (SQLi, XSS, Command, SSTI, XXE)
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: HTML Injection via 404 Page\033[0m"
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
PAYLOAD="injected-marker-abc123"
R=$(curl -s --max-time 10 "$T/$PAYLOAD" 2>/dev/null | head -c 3000)
if echo "$R" | grep -q "$PAYLOAD"; then
  # check if HTML tags survive
  R2=$(curl -s --max-time 10 "$T/<h1>$PAYLOAD</h1>" 2>/dev/null | head -c 3000)
  if echo "$R2" | grep -q "<h1>$PAYLOAD</h1>"; then
    emit "{\"title\":\"HTML injection in 404 page\",\"severity\":\"medium\",\"description\":\"404 page reflects URL path with HTML tags intact. Content spoofing and phishing page injection possible.\",\"remediation\":\"HTML-encode all reflected user input. Use generic 404 pages.\",\"cweId\":\"CWE-79\",\"owaspCategory\":\"A03:2025-Injection\"}"
  fi
fi
# check error page for stack trace
R3=$(curl -s --max-time 10 "$T/%00" 2>/dev/null | head -c 3000)
if echo "$R3" | grep -qi "stack trace\|at [a-zA-Z]+\.[a-zA-Z]+\|Traceback\|Exception in thread"; then
  emit "{\"title\":\"Stack trace in error page\",\"severity\":\"medium\",\"description\":\"Error pages reveal stack traces — internal file paths, library versions, and logic.\",\"remediation\":\"Disable detailed errors in production. Log internally, show generic message.\",\"cweId\":\"CWE-209\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
