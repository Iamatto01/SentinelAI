#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Editor & Temp File Exposure
# Description: Checks for vim swap, emacs backup, nano temp files
# Severity:    MEDIUM
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

# ── CATCH-ALL / SPA GUARD ───────────────────────────────────────────────────
# This probe treats "HTTP 200" as proof a file exists.  On a catch-all or SPA
# target EVERY path returns 200 with the same landing page, so the probe would
# report every path it tries as an exposed file — including fake criticals for
# .bash_history / .git-credentials.
#
# Guard: if the target serves an identical response for a path that provably
# cannot exist, the probe is meaningless here.  Prefer the baseline computed by
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
# meaning the response is the lander and not a distinct file.
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Editor & Temp File Exposure\033[0m"
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
PATHS="index.php~ index.html~ .index.php.swp .index.html.swp index.php.swp index.html.swp #index.php# #index.html# index.php.orig index.html.orig index.php.old index.html.old index.php.copy index.php.bak.bak .bash_history .zsh_history .mysql_history .psql_history .viminfo .gitconfig .git-credentials"
for P in $PATHS; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ]; then
    SZ=$(curl -s --max-time 8 "$T/$P" 2>/dev/null | wc -c)
    if [ "$SZ" -gt 50 ]; then
      is_catchall_response "$SZ" && continue
      SEV="medium"
      case "$P" in .bash_history|.zsh_history|.mysql_history|.psql_history|.git-credentials) SEV="critical";; esac
      DETAIL="May contain source code or configuration."
      if [ "$SEV" = "critical" ]; then DETAIL="Shell/DB history files contain executed commands and possibly credentials!"; fi
      emit "{\"title\":\"Editor/temp file exposed: /$P\",\"severity\":\"$SEV\",\"description\":\"Temporary or editor backup file /$P is readable. $DETAIL\",\"remediation\":\"Remove temp files from web root. Add *~ *.swp #*# patterns to deployment exclusions.\",\"cweId\":\"CWE-548\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
