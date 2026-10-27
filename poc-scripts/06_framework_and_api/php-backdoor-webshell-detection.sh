#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        PHP Backdoor & Webshell Detection
# Description: Scans for common webshell filenames
# Severity:    CRITICAL
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: PHP Backdoor & Webshell Detection\033[0m"
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
PATHS="c99.php c99shell.php r57.php shell.php cmd.php webshell.php backdoor.php hack.php evil.php spyshell.php wso.php b374k.php adminer.php c100.php x0ro.php 1337.php lamashell.php d0main.php x.php 1.php aaa.php tmp.php upload.php.up.php cmdshell.php phpspy.php"
for P in $PATHS; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ]; then
    BODY=$(curl -s --max-time 8 "$T/$P" 2>/dev/null | head -c 2000)
    if echo "$BODY" | grep -qi "passthru\|system(\|exec(\|shell_exec\|cmd\|command\|password\|eval("; then
      emit "{\"title\":\"Possible webshell: /$P\",\"severity\":\"critical\",\"description\":\"File /$P matches known webshell patterns and contains command execution functions. Server may be compromised.\",\"remediation\":\"Investigate immediately. Remove shell, audit access logs, rotate all credentials.\",\"cweId\":\"CWE-94\",\"owaspCategory\":\"A03:2025-Injection\"}"
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
