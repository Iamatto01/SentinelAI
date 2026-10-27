#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Database Dump & SQL File Exposure
# Description: Checks for exposed SQL dumps, CSV exports, and data files
# Severity:    CRITICAL
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Database Dump & SQL File Exposure\033[0m"
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
PATHS="dump.sql db.sql database.sql data.sql backup.sql users.sql emails.sql customers.sql accounts.sql passwords.sql export.csv data.csv users.csv emails.csv customers.csv database.db data.db db.sqlite database.sqlite app.db test.db dev.db prod.sql production.sql full_dump.sql"
for P in $PATHS; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ]; then
    CT=$(curl -s -I --max-time 8 "$T/$P" 2>/dev/null | grep -i content-type | tr -d '\r')
    if ! echo "$CT" | grep -qi "text/html"; then
      SZ=$(curl -s --max-time 8 "$T/$P" 2>/dev/null | wc -c)
      if [ "$SZ" -gt 100 ]; then
        emit "{\"title\":\"Database dump exposed: /$P\",\"severity\":\"critical\",\"description\":\"Database file /$P is downloadable (${SZ} bytes, $CT). May contain user data, credentials, and PII.\",\"remediation\":\"Remove database dumps from web root immediately. Audit for exposure history.\",\"cweId\":\"CWE-548\",\"owaspCategory\":\"A02:2025-Cryptographic Failures\"}"
      fi
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
