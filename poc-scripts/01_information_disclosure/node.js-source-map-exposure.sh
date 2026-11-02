#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform -- Security PoC Probe
# Name:        Node.js Source Map Exposure
# Description: Detects exposed .js.map files -- full original source disclosure
# Severity:    MEDIUM
# Category:    Information & Sensitive Data Disclosure
# Language:    bash
#
# Evidence contract
# -----------------
# Every emitted finding carries the request that produced it (url, status,
# bytes, contentType, server, method, bodyPreview, sourceCount) so the report
# can show the artifact instead of reprinting this script's own JSON.
#
# False-positive contract
# -----------------------
# A single-page application answers every unknown path with the same catch-all
# document. A source map is only a source map when the body is JSON carrying
# `"version"` AND `"mappings"`; a 143476-byte HTML shell is neither, and a body
# byte-identical to the catch-all baseline is suppressed before it is reported.
#
# Candidate discovery: .map files are derived from the script bundles the page
# actually references, so hashed builds (main.4f2a.js) are covered instead of
# a fixed guess list.
# ============================================================================
set -u

TARGET="${1:-${TARGET:-}}"
SCAN_ID="${SCAN_ID:-manual}"
DEPTH="${DEPTH:-standard}"

if [ -z "$TARGET" ]; then
  echo "[-] Error: Missing TARGET" >&2
  exit 1
fi
TARGET="${TARGET%/}"

echo ""
echo -e "\033[1;34m[*] [SentinelAI PoC] Running probe: Node.js Source Map Exposure\033[0m"
echo -e "\033[1;34m[*] Target: ${TARGET}\033[0m"
echo ""

# --- Core PoC Execution ---
emit() { printf '%s\n' "$1"; }

TMPDIR="${TMPDIR:-/tmp}"
WORK="$(mktemp -d "${TMPDIR%/}/sai-srcmap.XXXXXX" 2>/dev/null || echo "/tmp/sai-srcmap.$$")"
mkdir -p "$WORK" 2>/dev/null
trap 'rm -rf "$WORK"' EXIT

MAX_TIME=8
UA="SentinelAI/1.0 (+security-assessment)"
ORIGIN=$(printf '%s' "$TARGET" | sed -E 's#^(https?://[^/]+).*#\1#')

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
BASE_FILE="$WORK/baseline"
BASE_STATUS=$(curl -s -o "$BASE_FILE" -w "%{http_code}" \
  --max-time "$MAX_TIME" -A "$UA" "$TARGET/sai-probe-$RANDOM$RANDOM-absent" 2>/dev/null)
BASE_HASH=""
if [ "$BASE_STATUS" = "200" ]; then
  BASE_HASH=$(body_hash "$BASE_FILE")
  echo -e "\033[1;34m[*] Catch-all baseline: HTTP 200 ($(file_size "$BASE_FILE") bytes)\033[0m"
else
  echo -e "\033[1;34m[*] Catch-all baseline: HTTP ${BASE_STATUS:-000} (no fallback page)\033[0m"
fi

# A source map is JSON with "version" and "mappings" plus a source list.
looks_like_sourcemap() {
  f="$1"
  head -c 128 "$f" 2>/dev/null | grep -qiE '<!doctype|<html|<head|<body|<script' && return 1
  head -c 128 "$f" 2>/dev/null | grep -q '{' || return 1
  grep -q '"version"' "$f" 2>/dev/null || return 1
  grep -q '"mappings"' "$f" 2>/dev/null || return 1
  grep -q '"sources"' "$f" 2>/dev/null || grep -q '"sourcesContent"' "$f" 2>/dev/null
}

# --- Candidate discovery ----------------------------------------------------
PAGE="$WORK/page"
curl -s -o "$PAGE" --max-time "$MAX_TIME" -A "$UA" "$TARGET/" 2>/dev/null

CANDIDATES=""
add_candidate() {
  case " $CANDIDATES " in
    *" $1 "*) ;;
    *) CANDIDATES="$CANDIDATES $1" ;;
  esac
}

# Static fallbacks for builds whose map name cannot be derived.
for P in index.js.map main.js.map app.js.map bundle.js.map app.bundle.js.map \
         static/js/main.js.map assets/index.js.map dist/main.js.map js/app.js.map; do
  add_candidate "$TARGET/$P"
done

# Derived from the bundles the page actually loads: <bundle>.js -> <bundle>.js.map
# Handles quoted and unquoted attributes, protocol-relative URLs, and query
# strings, because hashed build names are exactly what a guess list misses.
DERIVED=0
for SRC in $(grep -oEi 'src=[^ >]+' "$PAGE" 2>/dev/null \
             | sed -e 's/^[Ss][Rr][Cc]=//' -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//" \
             | grep -iE '\.js' | head -12); do
  SRC="${SRC%%\?*}"
  case "$SRC" in
    http*) BUNDLE="$SRC" ;;
    //*)   BUNDLE="https:$SRC" ;;
    /*)    BUNDLE="$ORIGIN$SRC" ;;
    *)     BUNDLE="$TARGET/${SRC#./}" ;;
  esac
  add_candidate "$BUNDLE.map"
  DERIVED=$((DERIVED + 1))
done

COUNT=$(echo "$CANDIDATES" | wc -w | tr -d ' ')
echo -e "\033[1;34m[*] Probing ${COUNT} source-map candidate(s) (${DERIVED} derived from page bundles)\033[0m"

EMITTED=0
SEEN_HASHES=" "
BODY_FILE="$WORK/body"
HEAD_FILE="$WORK/headers"

for URL in $CANDIDATES; do
  STATUS=$(curl -s -o "$BODY_FILE" -D "$HEAD_FILE" -w "%{http_code}" \
    --max-time "$MAX_TIME" -A "$UA" "$URL" 2>/dev/null)

  [ "$STATUS" = "200" ] || continue

  SIZE=$(file_size "$BODY_FILE")
  # Size is not the discriminator -- the content gate below is. A tiny stub map
  # is still a map; an oversized HTML shell is still not.
  [ "${SIZE:-0}" -gt 50 ] || continue

  HASH=$(body_hash "$BODY_FILE")

  if [ -n "$BASE_HASH" ] && [ "$HASH" = "$BASE_HASH" ]; then
    echo -e "\033[1;33m[-] ${URL} is the application catch-all (${SIZE} bytes) -- suppressed\033[0m"
    continue
  fi
  case "$SEEN_HASHES" in
    *" $HASH "*) continue ;;
  esac

  looks_like_sourcemap "$BODY_FILE" || continue

  CTYPE=$(header_value "$HEAD_FILE" "content-type")
  SERVER=$(header_value "$HEAD_FILE" "server")

  # Count disclosed original files: this is what makes the finding concrete
  # instead of "a file was reachable".
  SOURCE_COUNT=$(grep -o '"sources"' "$BODY_FILE" 2>/dev/null | wc -l | tr -d ' ')
  TRACKED=$(tr ',' '\n' <"$BODY_FILE" 2>/dev/null | grep -c '"\.\./' 2>/dev/null)
  [ -n "$TRACKED" ] || TRACKED=0

  PREVIEW=$(head -c 400 "$BODY_FILE" | tr -d '\000-\010\013\014\016-\037')
  SEEN_HASHES="$SEEN_HASHES$HASH "
  EMITTED=$((EMITTED + 1))

  emit "{\"title\":\"Source map exposed: $(jsonstr "${URL#$TARGET}")\",\"severity\":\"medium\",\"description\":\"${URL} is publicly readable (HTTP 200, ${SIZE} bytes) and parses as a valid source map with a source list. It discloses unminified original source, file paths, and internal logic; ${TRACKED} original source reference(s) are recoverable.\",\"remediation\":\"Drop .map files from the production build (webpack devtool: false, Vite build.sourcemap: false) or deny /*.map at the reverse proxy, then rebuild.\",\"cweId\":\"CWE-548\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\",\"evidence\":{\"url\":\"$(jsonstr "$URL")\",\"status\":200,\"bytes\":${SIZE},\"contentType\":\"$(jsonstr "${CTYPE:-unknown}")\",\"server\":\"$(jsonstr "${SERVER:-unknown}")\",\"method\":\"GET\",\"sourceCount\":${TRACKED},\"bodyPreview\":\"$(jsonstr "$PREVIEW")\"}}"
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete. ${EMITTED} confirmed source-map exposure(s).\033[0m"