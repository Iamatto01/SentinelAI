#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        API Rate Limiting Test
# Description: Burst tests API endpoints for rate limiting
# Severity:    MEDIUM
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: API Rate Limiting Test\033[0m"
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
for EP in "api" "api/v1/users" "api/v1/products" "api/v1/data" "api/users" "api/data"; do
  LIMITED=0
  for I in $(seq 1 15); do
    R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 6 "$T/$EP" 2>/dev/null)
    if [ "$R" = "429" ]; then
      LIMITED=1
      break
    fi
  done
  if [ $LIMITED -eq 0 ] && [ "$R" = "200" ]; then
    emit "{\"title\":\"No rate limiting on API: /$EP\",\"severity\":\"medium\",\"description\":\"15 rapid requests to /$EP without 429 response. Data scraping, brute force, and DoS possible.\",\"remediation\":\"Implement rate limiting (e.g., 100 req/min per IP). Use API keys with quotas.\",\"cweId\":\"CWE-770\",\"owaspCategory\":\"A04:2025-Insecure Design\"}"
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
