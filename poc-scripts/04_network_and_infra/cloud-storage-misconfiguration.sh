#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Cloud Storage Misconfiguration
# Description: Checks for exposed S3 buckets, Azure blobs, GCS via common URL patterns
# Severity:    HIGH
# Category:    Network, Cloud & Infrastructure Security
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Cloud Storage Misconfiguration\033[0m"
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
# S3 patterns
for S3 in "$HOST.s3.amazonaws.com" "s3.amazonaws.com/$HOST" "$HOST.s3.us-east-1.amazonaws.com" "$HOST.s3.ap-southeast-1.amazonaws.com"; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "https://$S3" 2>/dev/null)
  if [ "$R" = "200" ]; then
    BODY=$(curl -s --max-time 8 "https://$S3" 2>/dev/null | head -c 1000)
    if echo "$BODY" | grep -q "ListBucketResult"; then
      emit "{\"title\":\"Exposed S3 bucket: $S3\",\"severity\":\"high\",\"description\":\"S3 bucket $S3 allows public listing. All objects are enumerable and downloadable.\",\"remediation\":\"Enable S3 Block Public Access. Use presigned URLs for access.\",\"cweId\":\"CWE-732\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
    fi
  fi
done
# Azure blob
R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "https://$HOST.blob.core.windows.net" 2>/dev/null)
if [ "$R" = "200" ] || [ "$R" = "400" ]; then
  BODY=$(curl -s --max-time 8 "https://$HOST.blob.core.windows.net/\$web?restype=container&comp=list" 2>/dev/null | head -c 500)
  if echo "$BODY" | grep -q "EnumerationResults"; then
    emit "{\"title\":\"Exposed Azure blob storage: $HOST\",\"severity\":\"high\",\"description\":\"Azure blob container for $HOST allows public listing.\",\"remediation\":\"Set public access level to Private. Use SAS tokens.\",\"cweId\":\"CWE-732\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
fi
# GCS
R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "https://storage.googleapis.com/$HOST" 2>/dev/null)
if [ "$R" = "200" ]; then
  BODY=$(curl -s --max-time 8 "https://storage.googleapis.com/$HOST" 2>/dev/null | head -c 500)
  if echo "$BODY" | grep -q "ListBucketResult"; then
    emit "{\"title\":\"Exposed GCS bucket: $HOST\",\"severity\":\"high\",\"description\":\"Google Cloud Storage bucket $HOST allows public listing.\",\"remediation\":\"Set uniform bucket-level access. Remove allUsers IAM binding.\",\"cweId\":\"CWE-732\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
