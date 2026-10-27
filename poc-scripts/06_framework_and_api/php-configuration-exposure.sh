#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        PHP Configuration Exposure
# Description: Checks for exposed .user.ini, .htaccess, php.ini files
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: PHP Configuration Exposure\033[0m"
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
PATHS=".user.ini .htaccess .htpasswd php.ini .env.example .env.local .env.production .env.backup .php-version .php-version.txt composer.json composer.lock package.json.bak"
for P in $PATHS; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ]; then
    BODY=$(curl -s --max-time 8 "$T/$P" 2>/dev/null | head -c 2000)
    if [ -n "$BODY" ] && ! echo "$BODY" | grep -qi "<!DOCTYPE\|<html"; then
      SEV="medium"
      case "$P" in .htpasswd|.env.production|.env.backup) SEV="high";; esac
      DETAIL="Reveals server configuration and access rules."
      if [ "$SEV" = "high" ]; then DETAIL="May contain credentials or password hashes!"; fi
      emit "{\"title\":\"Configuration file exposed: /$P\",\"severity\":\"$SEV\",\"description\":\"PHP/server configuration file /$P is readable. $DETAIL\",\"remediation\":\"Block dotfiles in web server config. Remove sensitive files from web root.\",\"cweId\":\"CWE-538\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
