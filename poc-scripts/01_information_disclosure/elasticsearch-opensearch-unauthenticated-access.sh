#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Elasticsearch/OpenSearch Unauthenticated Access
# Description: Direct check for open Elasticsearch cluster — data dump risk
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Elasticsearch/OpenSearch Unauthenticated Access\033[0m"
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
HOST=$(echo "$T" | sed 's|https\?://||' | cut -d/ -f1)
# try common ES ports on the host
for PORT in 9200 9201 5601; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 6 "http://$HOST:$PORT/" 2>/dev/null)
  if [ "$R" = "200" ] || [ "$R" = "401" ]; then
    BODY=$(curl -s --max-time 6 "http://$HOST:$PORT/" 2>/dev/null | head -c 500)
    if echo "$BODY" | grep -q "cluster_name\|You Know, for Search\|OpenSearch"; then
      emit "{\"title\":\"Elasticsearch open on port $PORT\",\"severity\":\"critical\",\"description\":\"Elasticsearch cluster is accessible on port $PORT without authentication. Full index and data dump possible.\",\"remediation\":\"Bind Elasticsearch to localhost only. Enable X-Pack security and authentication.\",\"cweId\":\"CWE-306\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
