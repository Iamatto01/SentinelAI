#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Robots.txt Sensitive Path Discovery
# Description: Parses robots.txt for Disallowed paths that reveal hidden functionality
# Severity:    INFO
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Robots.txt Sensitive Path Discovery\033[0m"
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
ROBOTS=$(curl -s --max-time 10 "$T/robots.txt" 2>/dev/null)
if [ -n "$ROBOTS" ] && [ ${#ROBOTS} -gt 10 ]; then
  # extract disallowed paths
  PATHS=$(echo "$ROBOTS" | grep -i "^Disallow:" | sed 's/Disallow: //i' | tr -d '\r' | grep -v "^$" | head -20)
  SENSITIVE="admin backup config secret private internal api test dev staging temp db database wp-admin phpmyadmin .git .env"
  for P in $PATHS; do
    for S in $SENSITIVE; do
      if echo "$P" | grep -qi "$S"; then
        # verify it's accessible
        CLEAN=$(echo "$P" | sed 's|^/||')
        R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$CLEAN" 2>/dev/null)
        if [ "$R" = "200" ]; then
          emit "{\"title\":\"Sensitive path in robots.txt is accessible: $P\",\"severity\":\"medium\",\"description\":\"robots.txt disallows $P but it returns HTTP 200. Hidden admin/backup/config areas are exposed.\",\"remediation\":\"Secure the disallowed paths with authentication. Remove sensitive entries from robots.txt.\",\"cweId\":\"CWE-548\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
        fi
      fi
    done
  done
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
