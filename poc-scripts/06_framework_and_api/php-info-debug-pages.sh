#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        PHP Info & Debug Pages
# Description: Detects phpinfo, phpinfo.php, info.php, and debug pages
# Severity:    HIGH
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: PHP Info & Debug Pages\033[0m"
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
PATHS="phpinfo phpinfo.php info.php infophp.php test.php php.php pi.php p.php phpinfo.php4 phpinfo.php5 phpinfo.html debug.php debug/index.php test/info.php server-info.php status.php admin/phpinfo.php"
for P in $PATHS; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ]; then
    BODY=$(curl -s --max-time 8 "$T/$P" 2>/dev/null | head -c 3000)
    if echo "$BODY" | grep -qi "phpinfo()\|PHP Version\|php_uname\|Configuration File"; then
      VER=$(echo "$BODY" | grep -oE "PHP Version [0-9.]+" | head -1)
      emit "{\"title\":\"phpinfo page exposed: /$P\",\"severity\":\"high\",\"description\":\"phpinfo() output is accessible at /$P ($VER). Reveals full paths, loaded modules, environment variables, and sometimes credentials.\",\"remediation\":\"Remove phpinfo files from production. Disable expose_php in php.ini.\",\"cweId\":\"CWE-200\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
