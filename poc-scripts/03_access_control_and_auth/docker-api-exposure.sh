#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Docker API Exposure
# Description: Detects unauthenticated Docker daemon — instant host takeover
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Docker API Exposure\033[0m"
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
for PORT in 2375 2376; do
  R=$(curl -s --max-time 6 "http://$HOST:$PORT/version" 2>/dev/null | head -c 500)
  if echo "$R" | grep -q "ApiVersion\|DockerVersion"; then
    emit "{\"title\":\"Docker daemon exposed on port $PORT\",\"severity\":\"critical\",\"description\":\"Docker API is accessible without authentication on port $PORT. Attackers can create privileged containers mounting the host filesystem — instant root on the host.\",\"remediation\":\"Never expose Docker daemon on TCP without TLS. Bind to unix socket only.\",\"cweId\":\"CWE-306\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
