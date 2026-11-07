#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Web Cache Deception Probe
# Description: Tests for cacheable authenticated pages with extension suffixes
# Severity:    HIGH
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

# ── CATCH-ALL / SPA GUARD ───────────────────────────────────────────────────
# This probe treats "HTTP 200 + text/html" as a cacheable authenticated page.
# On a catch-all or SPA target EVERY path returns 200 + text/html, so all
# PATH×EXT combinations match and the probe reports a site-wide false positive.
#
# Guard: if the target returns an identical response for a path that provably
# cannot exist, this probe is meaningless here.  Prefer the baseline computed by
# the pipeline (CATCHALL_* env vars); otherwise probe once ourselves so the
# script still behaves correctly when run standalone.
CATCHALL_LEN="${CATCHALL_LEN:-}"
if [ -z "$CATCHALL_LEN" ]; then
  CANARY=".sentinelai-nonexistent-$RANDOM$RANDOM"
  CANARY_R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$TARGET/$CANARY" 2>/dev/null)
  if [ "$CANARY_R" = "200" ]; then
    CATCHALL_STATUS="200"
    CATCHALL_LEN=$(curl -s --max-time 8 "$TARGET/$CANARY" 2>/dev/null | wc -c)
    echo -e "\033[1;33m[!] Catch-all detected: bogus path /$CANARY returned 200 (${CATCHALL_LEN} bytes).\033[0m"
  fi
fi

# Returns 0 (true) when SIZE matches the catch-all landing page size (2% tol),
# meaning the response is the lander and not a distinct page.
is_catchall_response() {
  local size="$1"
  [ -z "$CATCHALL_LEN" ] && return 1
  [ "$CATCHALL_LEN" -le 0 ] && return 1
  local diff=$(( size - CATCHALL_LEN ))
  [ "$diff" -lt 0 ] && diff=$(( -diff ))
  local tol=$(( CATCHALL_LEN / 50 ))   # 2%
  [ "$tol" -lt 16 ] && tol=16
  [ "$diff" -le "$tol" ]
}

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Web Cache Deception Probe\033[0m"
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
# try appending extensions to authenticated pages
PATHS="account/settings account/profile user/profile myaccount dashboard"
for P in $PATHS; do
  for EXT in ".css" ".js" ".png" ".ico"; do
    R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$P$EXT" 2>/dev/null)
    if [ "$R" = "200" ]; then
      CT=$(curl -s -I --max-time 8 "$T/$P$EXT" 2>/dev/null | grep -i "content-type\|cache-control" | tr -d '\r')
      if echo "$CT" | grep -qi "text/html" && ! echo "$CT" | grep -qi "no-store\|private"; then
        SZ=$(curl -s --max-time 8 "$T/$P$EXT" 2>/dev/null | wc -c)
        is_catchall_response "$SZ" && continue
        emit "{\"title\":\"Web cache deception possible: /$P$EXT\",\"severity\":\"high\",\"description\":\"Authenticated page /$P responds to extension suffix /$P$EXT with HTML content and cacheable headers. CDN may cache and serve to unauthenticated users.\",\"remediation\":\"Cache only static extensions. Set Cache-Control: no-store on authenticated pages.\",\"cweId\":\"CWE-524\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
      fi
    fi
  done
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
