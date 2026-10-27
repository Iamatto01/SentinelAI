#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Certificate Transparency Subdomain Discovery
# Description: Queries crt.sh for all subdomains from certificate logs
# Severity:    INFO
# Category:    Network, Cloud & Infrastructure Security
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Certificate Transparency Subdomain Discovery\033[0m"
echo -e "\033[1;34m[*] Target: $TARGET\033[0m"
echo ""

# Standard emit handler for standalone terminal execution
emit() {
  echo -e "\033[1;32m[+] VULNERABILITY CONFIRMED / FINDING EMITTED:\033[0m"
  echo "$1" | python3 -m json.tool 2>/dev/null || echo "    $1"
}

# --- Core PoC Execution ---
emit() { printf '%s\n' "$1"; }
HOST=$(echo "$TARGET" | sed 's|https\?://||' | cut -d/ -f1 | cut -d: -f1)
# query crt.sh certificate transparency logs
CRT=$(curl -s --max-time 20 "https://crt.sh/?q=%25.$HOST&output=json" 2>/dev/null | head -c 50000)
if [ -n "$CRT" ]; then
  SUBS=$(echo "$CRT" | grep -o '"common_name":"[^"]*"' | cut -d'"' -f4 | sort -u | head -30)
  COUNT=$(echo "$SUBS" | grep -c .)
  if [ "$COUNT" -gt 1 ]; then
    SUBLIST=$(echo "$SUBS" | tr '\n' ',' | sed 's/,$//')
    emit "{\"title\":\"$COUNT subdomains discovered via certificate transparency\",\"severity\":\"info\",\"description\":\"Certificate logs reveal $COUNT subdomains: $SUBLIST. Each is additional attack surface.\",\"remediation\":\"Review all subdomains for necessity. Decommission unused ones.\",\"cweId\":\"CWE-200\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
