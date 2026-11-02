#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# SentinelAI PoC -- Log File Exposure (deep scan)
#
# Evidence contract: one emitted finding per *distinct* exposed log body.
#   - exactly one HTTP request per candidate path (status + body + headers in
#     a single curl invocation, so the finding is reproducible)
#   - a catch-all fingerprint is taken first; any body byte-identical to the
#     application's fallback page is suppressed, never reported
#   - a body must look like machine-written log output, not an HTML shell
#   - duplicate bodies are hashed once and reported once
#   - every finding carries a real evidence object (url, status, bytes,
#     content-type, server, method, bodyPreview)
#
# False-positive reasoning: a single-page app answers 200 for every unknown
# path with the same shell. Reporting one CRITICAL per guessed filename is the
# classic way to manufacture a report full of duplicates, so the catch-all
# baseline is the gate, not the status code.
#
# Expects TARGET from the platform (also usable standalone: TARGET=... ./this)
# ---------------------------------------------------------------------------
set -u

TARGET="${TARGET:-}"
if [ -z "$TARGET" ]; then
  echo "[-] TARGET is not set" >&2
  exit 1
fi
TARGET="${TARGET%/}"

DEPTH="${DEPTH:-standard}"
SCAN_ID="${SCAN_ID:-manual}"

echo ""
echo -e "\033[1;34m[*] [SentinelAI PoC] Running probe: Log File Exposure (deep scan)\033[0m"
echo -e "\033[1;34m[*] Target: ${TARGET}\033[0m"
echo ""

# --- Core PoC Execution ---
emit() { printf '%s\n' "$1"; }

TMPDIR="${TMPDIR:-/tmp}"
WORK="$(mktemp -d "${TMPDIR%/}/sai-logexpo.XXXXXX" 2>/dev/null || echo "/tmp/sai-logexpo.$$")"
mkdir -p "$WORK" 2>/dev/null
trap 'rm -rf "$WORK"' EXIT

MAX_TIME=8
UA="SentinelAI/1.0 (+security-assessment)"

jsonstr() {
  printf '%s' "$1" \
    | tr -d '\000-\010\013\014\016-\037' \
    | tr '\t' ' ' \
    | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\r//g' \
    | awk 'BEGIN{ORS=""} {if (NR>1) printf "\\n"; print}'
}

body_hash() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  elif command -v md5sum >/dev/null 2>&1; then md5sum "$1" | awk '{print $1}'
  else printf '%s-%s' "$(wc -c <"$1" | tr -d ' ')" "$(cksum "$1" | awk '{print $1}')"
  fi
}

file_size() { wc -c <"$1" 2>/dev/null | tr -d ' '; }

header_value() {
  awk -v want="$2" '
    BEGIN { IGNORECASE = 1 }
    index(tolower($0), tolower(want) ":") == 1 {
      sub(/^[^:]*:[ ]*/, ""); sub(/\r$/, ""); print; exit
    }' "$1" 2>/dev/null
}

# --- Catch-all baseline -----------------------------------------------------
# One request to a path that cannot exist. Whatever comes back is the
# application's fallback page; anything identical to it is not an exposure.
BASE_FILE="$WORK/baseline"
BASE_HEAD="$WORK/baseline.headers"
BASE_STATUS=$(curl -s -o "$BASE_FILE" -D "$BASE_HEAD" -w "%{http_code}" \
  --max-time "$MAX_TIME" -A "$UA" "$TARGET/sai-probe-$RANDOM$RANDOM-absent" 2>/dev/null)
BASE_HASH=""
BASE_SIZE=0
if [ "$BASE_STATUS" = "200" ]; then
  BASE_HASH=$(body_hash "$BASE_FILE")
  BASE_SIZE=$(file_size "$BASE_FILE")
  echo -e "\033[1;34m[*] Catch-all baseline: /sai-probe-*-absent -> HTTP 200 (${BASE_SIZE} bytes)\033[0m"
else
  echo -e "\033[1;34m[*] Catch-all baseline: HTTP ${BASE_STATUS:-000} (no fallback page)\033[0m"
fi

# A body is a log file only if it looks like machine-written log lines and
# does not look like the application's HTML shell.
looks_like_log() {
  f="$1"
  if head -c 2048 "$f" 2>/dev/null | grep -qiE '<!doctype|<html|<head|<script|<body|window\.__|__NEXT_DATA__|<meta '; then
    return 1
  fi
  SIG=0
  # ISO / RFC timestamps
  grep -qE '[0-9]{4}-[0-9]{2}-[0-9]{2}[ T][0-9]{2}:[0-9]{2}:[0-9]{2}' "$f" 2>/dev/null && SIG=$((SIG + 1))
  # Apache / nginx common log timestamp: [30/Oct/2026:10:12:04 +0800]
  grep -qE '\[[0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}' "$f" 2>/dev/null && SIG=$((SIG + 1))
  # syslog timestamp: Oct 30 10:12:04
  grep -qE '^[A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}' "$f" 2>/dev/null && SIG=$((SIG + 1))
  # access-log request verb
  grep -qE '"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) /' "$f" 2>/dev/null && SIG=$((SIG + 1))
  # log levels / bracketed tags / threading ids
  grep -qiE '(^|[^a-z])(error|fatal|warn|warning|debug|trace|notice|crit)([^a-z]|$)' "$f" 2>/dev/null && SIG=$((SIG + 1))
  grep -qE '\[(pid|tid|[0-9]+)\]|\[[A-Za-z][A-Za-z0-9_.-]{1,15}\]' "$f" 2>/dev/null && SIG=$((SIG + 1))
  # runtime failure output
  grep -qiE 'stack trace|traceback \(|exception|undefined index|sqlstate|syntax error|errno' "$f" 2>/dev/null && SIG=$((SIG + 1))
  # client ip at line start (access logs)
  grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3} ' "$f" 2>/dev/null && SIG=$((SIG + 1))
  [ "$SIG" -ge 2 ]
}

PATHS="log logs log.txt error.log error_log debug.log access.log access_log app.log application.log server.log out.log output.log console.log system.log events.log security.log auth.log login.log mail.log laravel.log debug.log.1 error.log.1 access.log.1 logs/error.log var/log app/logs storage/logs"

echo -e "\033[1;34m[*] Probing $(echo "$PATHS" | wc -w | tr -d ' ') candidate paths (single request each)\033[0m"

EMITTED=0
SEEN_HASHES=" "
BODY_FILE="$WORK/body"
HEAD_FILE="$WORK/headers"

for P in $PATHS; do
  STATUS=$(curl -s -o "$BODY_FILE" -D "$HEAD_FILE" -w "%{http_code}" \
    --max-time "$MAX_TIME" -A "$UA" "$TARGET/$P" 2>/dev/null)

  # 401/403 is a real signal: the path is routed separately from the
  # catch-all, which means a deny rule was written for it on purpose.
  if [ "$STATUS" = "401" ] || [ "$STATUS" = "403" ]; then
    CTYPE=$(header_value "$HEAD_FILE" "content-type")
    SERVER=$(header_value "$HEAD_FILE" "server")
    EMITTED=$((EMITTED + 1))
    emit "{\"title\":\"Log path reachable but denied: /$P\",\"severity\":\"low\",\"description\":\"GET /$P returns HTTP ${STATUS} while unknown paths return HTTP ${BASE_STATUS:-000}. The path is routed separately from the application catch-all, so a log file is likely present there and is only protected by an access rule in front of it.\",\"remediation\":\"Remove log files from the web root instead of relying on a proxy deny rule, then re-test the path.\",\"cweId\":\"CWE-538\",\"owaspCategory\":\"A01:2025-Broken Access Control\",\"evidence\":{\"url\":\"$(jsonstr "$TARGET/$P")\",\"status\":${STATUS},\"method\":\"GET\",\"contentType\":\"$(jsonstr "${CTYPE:-unknown}")\",\"server\":\"$(jsonstr "${SERVER:-unknown}")\",\"observed\":\"routed path, access denied\"}}"
    continue
  fi

  [ "$STATUS" = "200" ] || continue

  SIZE=$(file_size "$BODY_FILE")
  [ "${SIZE:-0}" -gt 0 ] || continue

  HASH=$(body_hash "$BODY_FILE")

  # Identical to the catch-all shell, or a duplicate of an already reported
  # body: not a distinct exposure, so it must not become another card.
  if [ -n "$BASE_HASH" ] && [ "$HASH" = "$BASE_HASH" ]; then
    echo -e "\033[1;33m[-] /$P is the application catch-all (${SIZE} bytes) -- suppressed\033[0m"
    continue
  fi
  case "$SEEN_HASHES" in
    *" $HASH "*) continue ;;
  esac

  looks_like_log "$BODY_FILE" || continue

  CTYPE=$(header_value "$HEAD_FILE" "content-type")
  CLEN=$(header_value "$HEAD_FILE" "content-length")
  SERVER=$(header_value "$HEAD_FILE" "server")

  SEV="high"
  DETAIL="May contain internal paths, user data, and error output."
  if grep -qiE 'password|passwd|api[_-]?key|secret|token|authorization:|set-cookie' "$BODY_FILE" 2>/dev/null; then
    SEV="critical"
    DETAIL="Contains credentials, tokens, or session material."
  fi

  PREVIEW=$(head -c 480 "$BODY_FILE" | tr -d '\000-\010\013\014\016-\037')
  SEEN_HASHES="$SEEN_HASHES$HASH "
  EMITTED=$((EMITTED + 1))

  emit "{\"title\":\"Log file exposed: /$P\",\"severity\":\"$SEV\",\"description\":\"Log file /$P is directly readable over HTTP (HTTP 200, ${SIZE} bytes). $DETAIL\",\"remediation\":\"Move log files outside the web root, deny direct access at the reverse proxy for /logs and /*.log, and enable log rotation.\",\"cweId\":\"CWE-532\",\"owaspCategory\":\"A09:2025-Security Logging and Monitoring Failures\",\"evidence\":{\"url\":\"$(jsonstr "$TARGET/$P")\",\"status\":200,\"bytes\":${SIZE},\"contentType\":\"$(jsonstr "${CTYPE:-unknown}")\",\"contentLengthHeader\":\"$(jsonstr "${CLEN:-none}")\",\"server\":\"$(jsonstr "${SERVER:-unknown}")\",\"method\":\"GET\",\"bodyPreview\":\"$(jsonstr "$PREVIEW")\"}}"
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete. ${EMITTED} confirmed log exposure(s).\033[0m"