#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Database Admin Interfaces Exposure
# Description: Detects phpMyAdmin, Adminer, pgAdmin, Mongo Express, Redis Commander
# Severity:    CRITICAL
# Category:    Broken Access Control & Authentication
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Database Admin Interfaces Exposure\033[0m"
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
PATHS="phpmyadmin phpMyAdmin pma PMA myadmin mysql mysqladmin adminer adminer.php adminer-4.8.1.php pgadmin pgadmin4 mongo mongo-express mongoadmin redis redis-commander elasticsearch kibana kibana/app/home couchdb _utils (couchdb) solr solr/admin"
for P in $PATHS; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ]; then
    BODY=$(curl -s --max-time 8 "$T/$P" 2>/dev/null | head -c 600)
    if echo "$BODY" | grep -qi "phpmyadmin\|adminer\|pgadmin\|mongo\|redis\|elasticsearch\|kibana\|couchdb\|solr\|login\|sign in"; then
      emit "{\"title\":\"Database admin interface exposed: /$P\",\"severity\":\"critical\",\"description\":\"Database management interface /$P is publicly accessible. Default credentials or exploits give full database access.\",\"remediation\":\"Remove database admin tools from production web roots. Restrict to internal networks.\",\"cweId\":\"CWE-798\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
