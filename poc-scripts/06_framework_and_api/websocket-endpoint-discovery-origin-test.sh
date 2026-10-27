#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        WebSocket Endpoint Discovery & Origin Test
# Description: Finds WebSocket endpoints and tests origin validation
# Severity:    HIGH
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: WebSocket Endpoint Discovery & Origin Test\033[0m"
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
# common WS paths
PATHS="ws socket socket.io websocket chat realtime live events stream notifications pubsub mqtt stomp/sockjs sockjs"
for P in $PATHS; do
  R=$(curl -s -o /dev/null -w "%{http_code}" -H "Upgrade: websocket" -H "Connection: Upgrade" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" -H "Sec-WebSocket-Version: 13" -H "Origin: https://evil.example.com" --max-time 8 "$T/$P" 2>/dev/null)
  if [ "$R" = "101" ]; then
    emit "{\"title\":\"WebSocket accepts cross-origin: /$P\",\"severity\":\"high\",\"description\":\"WebSocket endpoint /$P upgrades connection from evil.example.com origin. Cross-Site WebSocket Hijacking — authenticated WS sessions can be hijacked from attacker pages.\",\"remediation\":\"Validate Origin header against whitelist. Use authentication tokens in first WS message.\",\"cweId\":\"CWE-346\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  elif [ "$R" = "400" ]; then
    # check if origin was the rejection reason
    BODY=$(curl -s -H "Upgrade: websocket" -H "Connection: Upgrade" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" -H "Sec-WebSocket-Version: 13" -H "Origin: https://evil.example.com" --max-time 8 "$T/$P" 2>/dev/null | head -c 300)
    if ! echo "$BODY" | grep -qi "origin"; then
      # try without origin — if 101, origin is ignored
      R2=$(curl -s -o /dev/null -w "%{http_code}" -H "Upgrade: websocket" -H "Connection: Upgrade" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" -H "Sec-WebSocket-Version: 13" --max-time 8 "$T/$P" 2>/dev/null)
      if [ "$R2" = "101" ]; then
        emit "{\"title\":\"WebSocket no origin validation: /$P\",\"severity\":\"high\",\"description\":\"WebSocket /$P upgrades without Origin validation. Any website can connect.\",\"remediation\":\"Validate Origin header. Implement per-connection authentication.\",\"cweId\":\"CWE-346\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
      fi
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
