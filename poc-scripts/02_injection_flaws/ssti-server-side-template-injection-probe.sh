#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        SSTI (Server-Side Template Injection) Probe
# Description: Tests for template injection via math expression evaluation
# Severity:    CRITICAL
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: SSTI (Server-Side Template Injection) Probe\033[0m"
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
# SSTI canary: 7*7=49 in multiple template syntaxes
PAYLOADS="{{7*7}} ${7*7} <%= 7*7 %> {{7*'7'}} #{7*7} {*7*7} {{ 7 * 7 }}"
PARAMS="name template page view render q search title msg message content"
for P in $PARAMS; do
  for PL in "{{7*7}}" "\49" "<%= 7*7 %>"; do
    RESP=$(curl -s --max-time 8 "$T?$P=$(echo $PL | sed 's/{/%7B/g; s/}/%7D/g')" 2>/dev/null | head -c 5000)
    if echo "$RESP" | grep -q "49"; then
      # verify it's not just coincidence — check the payload isn't reflected as-is
      if ! echo "$RESP" | grep -q "$PL"; then
        emit "{\"title\":\"SSTI detected: ?$P= parameter\",\"severity\":\"critical\",\"description\":\"Template expression evaluates at parameter ?$P= — 7*7 rendered as 49. Remote Code Execution likely possible.\",\"remediation\":\"Never pass user input directly to template engines. Use template context variables instead.\",\"cweId\":\"CWE-1336\",\"owaspCategory\":\"A03:2025-Injection\"}"
      fi
    fi
  done
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
