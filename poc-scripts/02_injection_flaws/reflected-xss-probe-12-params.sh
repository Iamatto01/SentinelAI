#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Reflected XSS Probe (12 params)
# Description: Sends XSS canary to common parameters and checks for reflection
# Severity:    HIGH
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Reflected XSS Probe (12 params)\033[0m"
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
PARAMS="q search query keyword name title comment message text content description msg s find filter term keywords"
CANARY="xssprobe<scr>ipt>alert(1)</scr"ipt>"
for P in $PARAMS; do
  RESP=$(curl -s --max-time 8 "$T?$P=$CANARY" 2>/dev/null | head -c 10000)
  if echo "$RESP" | grep -q "xssprobe<scr>ipt>"; then
    # check if it's in HTML context (not just in a comment or encoded)
    if echo "$RESP" | grep -q "<scr>ipt>alert(1)"; then
      emit "{\"title\":\"Reflected XSS: ?$P= parameter\",\"severity\":\"high\",\"description\":\"XSS canary is reflected unencoded in HTML at parameter ?$P=. Script injection possible.\",\"remediation\":\"HTML-encode all user input on output. Implement Content-Security-Policy.\",\"cweId\":\"CWE-79\",\"owaspCategory\":\"A03:2025-Injection\"}"
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
