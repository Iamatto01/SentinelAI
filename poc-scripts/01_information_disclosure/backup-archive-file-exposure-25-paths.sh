#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Backup & Archive File Exposure (25 paths)
# Description: Batch-checks for exposed backup files (.bak, .sql, .zip, .tar.gz, .7z)
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Backup & Archive File Exposure (25 paths)\033[0m"
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
PATHS="backup.zip backup.tar.gz backup.7z backup.sql db.sql database.sql dump.sql site.zip www.zip html.zip web.zip backup.bak index.php.bak index.bak config.php.bak config.bak wp-config.php.bak .bak database.bak site.bak backup.tar site.tar public.tar app.tar.gz backup.rar data.sql users.sql admin.sql"
for P in $PATHS; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ]; then
    CT=$(curl -s -I --max-time 8 "$T/$P" 2>/dev/null | grep -i content-type | head -1)
    emit "{\"title\":\"Exposed backup file: $P\",\"severity\":\"critical\",\"description\":\"Backup file $P is publicly downloadable. $CT May contain full source code, database dumps, or credentials.\",\"remediation\":\"Remove backup files from web root. Restrict access to archive extensions.\",\"cweId\":\"CWE-548\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
