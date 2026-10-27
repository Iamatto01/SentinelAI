#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Insecure Deserialization Probe (PHP/Java/Python)
# Description: Tests for serialized object injection points
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Insecure Deserialization Probe (PHP/Java/Python)\033[0m"
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
# PHP serialized object in cookies/params
PHP_PAYLOAD='O:8:"stdClass":0:{}'
R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 -b "session=$PHP_PAYLOAD" "$T/" 2>/dev/null)
if [ "$R" = "500" ]; then
  emit "{\"title\":\"PHP deserialization error on session cookie\",\"severity\":\"high\",\"description\":\"Server returns 500 when session cookie contains serialized PHP object — deserialization of untrusted data. POP chain exploitation possible.\",\"remediation\":\"Never unserialize() user input. Use JSON. Implement allowed-classes whitelist.\",\"cweId\":\"CWE-502\",\"owaspCategory\":\"A08:2025-Software and Data Integrity Failures\"}"
fi
# Java serialized data probe (common in viewstate-like params)
JAVA_PAYLOAD=$(printf '\xac\xed\x00\x05test')
R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 --data-urlencode "data=$JAVA_PAYLOAD" "$T/" 2>/dev/null)
if [ "$R" = "500" ]; then
  emit "{\"title\":\"Java deserialization error detected\",\"severity\":\"high\",\"description\":\"Server errors on Java serialized data (\xac\xed magic bytes) — potential Java deserialization gadget chain (Commons Collections, etc.).\",\"remediation\":\"Avoid native Java serialization for user data. Use JSON. Implement look-ahead deserialization filters.\",\"cweId\":\"CWE-502\",\"owaspCategory\":\"A08:2025-Software and Data Integrity Failures\"}"
fi
# Python pickle probe
PY_PAYLOAD=$(printf 'gASVtest')
R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 --data-urlencode "data=$PY_PAYLOAD" "$T/api" 2>/dev/null)
if [ "$R" = "500" ]; then
  emit "{\"title\":\"Python pickle deserialization error\",\"severity\":\"high\",\"description\":\"Server errors on pickle-formatted data — potential RCE via pickle payload.\",\"remediation\":\"Never pickle.loads() user input. Use JSON.\",\"cweId\":\"CWE-502\",\"owaspCategory\":\"A08:2025-Software and Data Integrity Failures\"}"
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
