#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        WordPress Security Audit (12 checks)
# Description: wp-config exposure, xmlrpc, wp-cron, readme, version disclosure, user enumeration
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: WordPress Security Audit (12 checks)\033[0m"
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
# wp-config backups
for P in "wp-config.php.bak" "wp-config.php~" "wp-config.txt" "wp-config.php.save" ".wp-config.php.swp"; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ]; then
    emit "{\"title\":\"WordPress config backup exposed: $P\",\"severity\":\"critical\",\"description\":\"wp-config backup file is readable — database credentials exposed.\",\"remediation\":\"Delete backup files immediately.\",\"cweId\":\"CWE-548\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
done
# XML-RPC
R=$(curl -s -o /dev/null -w "%{http_code}" -X POST -d "<methodCall><methodName>system.listMethods</methodName></methodCall>" --max-time 10 "$T/xmlrpc.php" 2>/dev/null)
if [ "$R" = "200" ]; then
  BODY=$(curl -s -X POST -d "<methodCall><methodName>system.listMethods</methodName></methodCall>" --max-time 10 "$T/xmlrpc.php" 2>/dev/null | head -c 200)
  if echo "$BODY" | grep -q "system.listMethods"; then
    emit "{\"title\":\"WordPress XML-RPC enabled\",\"severity\":\"medium\",\"description\":\"XML-RPC interface is active — brute-force amplification (system.multicall) and pingback DDoS possible.\",\"remediation\":\"Disable XML-RPC or block access to xmlrpc.php.\",\"cweId\":\"CWE-16\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
fi
# wp-cron
R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/wp-cron.php" 2>/dev/null)
if [ "$R" = "200" ]; then
  emit "{\"title\":\"WordPress wp-cron.php accessible\",\"severity\":\"low\",\"description\":\"wp-cron.php is publicly accessible — can be triggered externally for DoS.\",\"remediation\":\"Disable WP_CRON and use system cron. Block external access.\",\"cweId\":\"CWE-400\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi
# readme/license files (version disclosure)
for P in "readme.html" "license.txt"; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ]; then
    VER=$(curl -s --max-time 8 "$T/$P" 2>/dev/null | grep -oP "Version [0-9.]+" | head -1)
    emit "{\"title\":\"WordPress version disclosure: /$P ($VER)\",\"severity\":\"low\",\"description\":\"WordPress version is disclosed via $P. $VER Attackers can target known CVEs for this version.\",\"remediation\":\"Remove readme.html and license.txt from web root.\",\"cweId\":\"CWE-200\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
done
# user enumeration via REST API
R=$(curl -s --max-time 10 "$T/wp-json/wp/v2/users" 2>/dev/null | head -c 2000)
if echo "$R" | grep -q "slug"; then
  USERS=$(echo "$R" | grep -o '"slug":"[^"]*"' | cut -d'"' -f4 | tr '\n' ',' | sed 's/,$//')
  emit "{\"title\":\"WordPress user enumeration via REST API\",\"severity\":\"medium\",\"description\":\"Usernames are enumerable via /wp-json/wp/v2/users: $USERS. Facilitates targeted credential attacks.\",\"remediation\":\"Block /wp-json/wp/v2/users endpoint or restrict via plugin.\",\"cweId\":\"CWE-204\",\"owaspCategory\":\"A07:2025-Identification and Authentication Failures\"}"
fi
# user enumeration via author archive
for I in 1 2 3; do
  R=$(curl -s -o /dev/null -w "%{http_code}%{redirect_url}" --max-time 8 "$T/?author=$I" 2>/dev/null)
  if echo "$R" | grep -q "200"; then
    LOC=$(echo "$R" | grep -oP "author/[^/]+")
    if [ -n "$LOC" ]; then
      emit "{\"title\":\"WordPress user enumeration via ?author=$I\",\"severity\":\"low\",\"description\":\"Author archive redirects reveal username: $LOC\",\"remediation\":\"Disable author archives or use plugin to mask usernames.\",\"cweId\":\"CWE-204\",\"owaspCategory\":\"A07:2025-Identification and Authentication Failures\"}"
      break
    fi
  fi
done
# debug log
R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/wp-content/debug.log" 2>/dev/null)
if [ "$R" = "200" ]; then
  emit "{\"title\":\"WordPress debug.log exposed\",\"severity\":\"high\",\"description\":\"wp-content/debug.log is readable — may contain database errors, paths, and sensitive data.\",\"remediation\":\"Disable WP_DEBUG in production. Delete debug.log.\",\"cweId\":\"CWE-532\",\"owaspCategory\":\"A09:2025-Security Logging and Monitoring Failures\"}"
fi
# uploads directory listing
BODY=$(curl -s --max-time 8 "$T/wp-content/uploads/" 2>/dev/null | head -c 500)
if echo "$BODY" | grep -qi "Index of"; then
  emit "{\"title\":\"WordPress uploads directory listing\",\"severity\":\"low\",\"description\":\"wp-content/uploads/ has directory listing enabled — all uploaded files enumerable.\",\"remediation\":\"Disable directory listing on uploads.\",\"cweId\":\"CWE-548\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
