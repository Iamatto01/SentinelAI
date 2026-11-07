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

# ── CATCH-ALL / SPA GUARD ───────────────────────────────────────────────────
# This probe treats "200 without 429" as proof an API endpoint exists and is
# unprotected.  On a catch-all or SPA target a nonexistent /api/v1/users still
# returns 200 (the landing page), so the probe reports every hardcoded endpoint
# as an unprotected API — a false positive per endpoint.
#
# Guard: if a path that provably cannot exist returns 200, "200" carries no
# evidence of existence.  Prefer the baseline computed by the pipeline
# (CATCHALL_* env vars); otherwise probe once ourselves so the script still
# behaves correctly when run standalone.
CATCHALL_LEN="${CATCHALL_LEN:-}"
CANARY_R=""
if [ -z "$CATCHALL_LEN" ]; then
  CANARY=".sentinelai-nonexistent-$RANDOM$RANDOM"
  CANARY_R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$TARGET/$CANARY" 2>/dev/null)
  if [ "$CANARY_R" = "200" ]; then
    CATCHALL_STATUS="200"
    CATCHALL_LEN=$(curl -s --max-time 8 "$TARGET/$CANARY" 2>/dev/null | wc -c)
    echo -e "\033[1;33m[!] Catch-all detected: bogus path /$CANARY returned 200 (${CATCHALL_LEN} bytes).\033[0m"
  fi
fi

# Returns 0 (true) when the response body length matches the catch-all landing
# page (2% tol) — i.e. the endpoint does not exist and we got the lander.
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
  # Pre-check: does this endpoint return something distinguishable from the
  # catch-all lander?  If not, "200" proves nothing — skip the burst entirely
  # (saves 15 requests and prevents a guaranteed false positive).
  PRE_BODY=$(curl -s --max-time 8 "$T/$EP" 2>/dev/null)
  PRE_SZ=$(printf '%s' "$PRE_BODY" | wc -c)
  if is_catchall_response "$PRE_SZ"; then
    echo -e "\033[1;33m[!] Skipping /$EP — response is the catch-all lander (${PRE_SZ} bytes), endpoint not verified to exist.\033[0m"
    continue
  fi
  # An API endpoint must return machine-readable data, not an HTML page.
  PRE_CT=$(curl -s -I --max-time 8 "$T/$EP" 2>/dev/null | grep -i "^content-type" | tr -d '\r')
  if echo "$PRE_CT" | grep -qi "text/html" && ! echo "$PRE_BODY" | head -c 200 | grep -q '[{[]'; then
    echo -e "\033[1;33m[!] Skipping /$EP — content-type is HTML with no JSON payload; not an API endpoint.\033[0m"
    continue
  fi

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
