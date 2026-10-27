#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Default Installation Pages (12 paths)
# Description: Detects unconfigured software — default Apache/Nginx/IIS pages, installers
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Default Installation Pages (12 paths)\033[0m"
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
PATHS="install install.php installer setup setup.php admin/install wp-admin/install.php install/ setup/ config.php install.php?step=1 database.sql schema.sql README.md INSTALL.md CHANGELOG.md"
for P in $PATHS; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ]; then
    BODY=$(curl -s --max-time 8 "$T/$P" 2>/dev/null | head -c 2000)
    if echo "$BODY" | grep -qi "install\|setup\|configuration\|wizard"; then
      emit "{\"title\":\"Installation/setup page exposed: /$P\",\"severity\":\"high\",\"description\":\"Installation or setup wizard is accessible at /$P. Attackers may reconfigure the application or create admin accounts.\",\"remediation\":\"Delete installer files after setup. Block access to install/setup paths.\",\"cweId\":\"CWE-16\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
