#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Prototype Pollution Probe (client-side)
# Description: Checks JS for __proto__ handling and DOM XSS sinks
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Prototype Pollution Probe (client-side)\033[0m"
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
BODY=$(curl -s --max-time 10 "$T" 2>/dev/null)
# check for vulnerable patterns
if echo "$BODY" | grep -q "__proto__\|Object.assign\|merge(\|extend(\|lodash"; then
  # check for jQuery with known vulnerable versions
  JQ=$(echo "$BODY" | grep -o 'jquery[^"]*\.js' | head -1)
  if echo "$JQ" | grep -qE "1\.[0-9]\.|2\.[0-2]\."; then
    emit "{\"title\":\"Potentially vulnerable jQuery version: $JQ\",\"severity\":\"medium\",\"description\":\"Old jQuery version detected ($JQ). Known prototype pollution (CVE-2019-11358) and XSS (CVE-2020-11022/11023) vulnerabilities.\",\"remediation\":\"Upgrade jQuery to 3.5+ or latest.\",\"cweId\":\"CWE-1321\",\"owaspCategory\":\"A06:2025-Vulnerable and Outdated Components\"}"
  fi
fi
# check for dangerous DOM sinks
if echo "$BODY" | grep -q "innerHTML\s*=\|document.write(\|eval(\|setTimeout(['\"]"; then
  emit "{\"title\":\"Dangerous DOM XSS sinks present\",\"severity\":\"low\",\"description\":\"Page uses innerHTML, document.write, or eval — potential DOM XSS if user input reaches these sinks.\",\"remediation\":\"Use textContent instead of innerHTML. Avoid eval and document.write.\",\"cweId\":\"CWE-79\",\"owaspCategory\":\"A03:2025-Injection\"}"
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
