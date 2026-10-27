#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Log File Exposure (deep scan)
# Description: Checks for exposed log files — credentials, tokens, internal paths
# Severity:    HIGH
# Category:    Information & Sensitive Data Disclosure
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Log File Exposure (deep scan)\033[0m"
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
PATHS="log logs log.txt error.log error_log debug.log access.log access_log app.log application.log server.log out.log output.log console.log system.log events.log security.log auth.log login.log mail.log laravel.log debug.log.1 error.log.1 access.log.1 logs/error.log var/log app/logs storage/logs"
for P in $PATHS; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ]; then
    SZ=$(curl -s --max-time 8 "$T/$P" 2>/dev/null | wc -c)
    if [ "$SZ" -gt 500 ]; then
      # check for sensitive content
      BODY=$(curl -s --max-time 8 "$T/$P" 2>/dev/null | head -c 5000)
      SEV="high"
      if echo "$BODY" | grep -qi "password\|token\|authorization\|session\|secret\|api.key"; then
        SEV="critical"
      fi
      DETAIL="May contain internal paths, user data, and errors."
      if [ "$SEV" = "critical" ]; then DETAIL="Contains credentials, tokens, or session data!"; fi
      emit "{\"title\":\"Log file exposed: /$P\",\"severity\":\"$SEV\",\"description\":\"Log file /$P is readable (${SZ} bytes). $DETAIL\",\"remediation\":\"Move logs outside web root. Restrict access. Implement log rotation.\",\"cweId\":\"CWE-532\",\"owaspCategory\":\"A09:2025-Security Logging and Monitoring Failures\"}"
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
