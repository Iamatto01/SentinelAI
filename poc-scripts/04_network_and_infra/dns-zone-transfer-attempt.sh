#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        DNS Zone Transfer Attempt
# Description: Tests for AXFR — full DNS zone disclosure
# Severity:    HIGH
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: DNS Zone Transfer Attempt\033[0m"
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
if command -v dig >/dev/null 2>&1; then
  NS=$(dig +short NS "$HOST" 2>/dev/null | head -3)
  for NAMESERVER in $NS; do
    AXFR=$(dig AXFR "$HOST" @"$NAMESERVER" 2>/dev/null | grep -c "IN")
    if [ "$AXFR" -gt 5 ]; then
      emit "{\"title\":\"DNS zone transfer allowed: $NAMESERVER\",\"severity\":\"high\",\"description\":\"Nameserver $NAMESERVER allows AXFR zone transfer ($AXFR records). Internal hostnames and infrastructure fully exposed.\",\"remediation\":\"Disable zone transfers to unauthorized servers (allow-transfer { none; }).\",\"cweId\":\"CWE-200\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
    fi
  done
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
