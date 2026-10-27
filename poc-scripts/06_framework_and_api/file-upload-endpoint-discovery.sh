#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        File Upload Endpoint Discovery
# Description: Finds file upload forms and endpoints
# Severity:    INFO
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: File Upload Endpoint Discovery\033[0m"
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
PATHS="upload uploads file/upload api/upload api/v1/upload media/upload image/upload avatar/upload attachment/upload file file/upload.php upload.php uploadfile fileupload"
for P in $PATHS; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ] || [ "$R" = "405" ]; then
    # check for form
    BODY=$(curl -s --max-time 8 "$T/$P" 2>/dev/null | head -c 3000)
    if echo "$BODY" | grep -qi "enctype.*multipart\|type.*file\|upload"; then
      emit "{\"title\":\"File upload endpoint: /$P\",\"severity\":\"info\",\"description\":\"File upload endpoint found at /$P (HTTP $R). If upload validation is weak, webshell upload possible.\",\"remediation\":\"Validate file type, size, and content. Store uploads outside web root.\",\"cweId\":\"CWE-434\",\"owaspCategory\":\"A04:2025-Insecure Design\"}"
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
