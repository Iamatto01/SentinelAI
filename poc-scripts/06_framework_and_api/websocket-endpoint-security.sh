#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        WebSocket Endpoint Security
# Description: Discovers WebSocket endpoints and checks origin validation
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: WebSocket Endpoint Security\033[0m"
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
# discover WS endpoints from page source
BODY=$(curl -s --max-time 10 "$T" 2>/dev/null)
WS_PATHS=$(echo "$BODY" | grep -o 'wss\?://[^"''' ]*\|["''']/[a-z0-9_-]*ws[a-z0-9/_-]*' | head -5)
if [ -n "$WS_PATHS" ]; then
  # test cross-origin handshake
  for WS in $WS_PATHS; do
    if echo "$WS" | grep -q "^wss\?://"; then
      FULL="$WS"
    else
      FULL="$T$WS"
    fi
    HTTPURL=$(echo "$FULL" | sed 's/^ws/http/; s/^wss/https/')
    R=$(curl -s -o /dev/null -w "%{http_code}" -H "Origin: https://evil-origin-test.com" -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" --max-time 10 "$HTTPURL" 2>/dev/null)
    if [ "$R" = "101" ]; then
      emit "{\"title\":\"WebSocket accepts cross-origin connections: $WS\",\"severity\":\"medium\",\"description\":\"WebSocket endpoint $WS upgrades connections from any origin. Cross-Site WebSocket Hijacking possible — attacker's page can connect using victim's cookies.\",\"remediation\":\"Validate Origin header against allowlist during WebSocket handshake.\",\"cweId\":\"CWE-346\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
    fi
  done
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
