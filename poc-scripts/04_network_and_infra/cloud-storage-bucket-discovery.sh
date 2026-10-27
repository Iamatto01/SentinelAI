#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Cloud Storage Bucket Discovery
# Description: Finds S3/Azure/GCS buckets referenced in page source
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Cloud Storage Bucket Discovery\033[0m"
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
BODY=$(curl -s -L --max-time 15 "$T" 2>/dev/null)
# S3 buckets
S3=$(echo "$BODY" | grep -oE '[a-zA-Z0-9.-]+\.s3[.-][a-zA-Z0-9.-]*\.amazonaws\.com' | sort -u | head -5)
for B in $S3; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "https://$B" 2>/dev/null)
  if [ "$R" = "200" ]; then
    LISTING=$(curl -s --max-time 8 "https://$B" 2>/dev/null | head -c 500)
    if echo "$LISTING" | grep -q "<ListBucketResult"; then
      emit "{\"title\":\"Open S3 bucket: $B\",\"severity\":\"critical\",\"description\":\"S3 bucket $B allows public listing. All contents downloadable.\",\"remediation\":\"Enable S3 Block Public Access. Use presigned URLs for access.\",\"cweId\":\"CWE-732\",\"owaspCategory\":\"A01:2025-Broken Access Control\"}"
    fi
  fi
done
# Azure blobs
AZ=$(echo "$BODY" | grep -oE '[a-zA-Z0-9.-]+\.blob\.core\.windows\.net' | sort -u | head -5)
for B in $AZ; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "https://$B?restype=container&comp=list" 2>/dev/null)
  if [ "$R" = "200" ]; then
    emit "{\"title\":\"Open Azure blob container: $B\",\"severity\":\"critical\",\"description\":\"Azure blob container $B allows public listing via REST API.\",\"remediation\":\"Set public access level to Private. Use SAS tokens.\",\"cweId\":\"CWE-732\",\"owaspCategory\":\"A01:2025-Broken Access Control\"}"
  fi
done
# GCS
GCS=$(echo "$BODY" | grep -oE 'storage\.googleapis\.com/[a-zA-Z0-9.-]+' | sort -u | head -5)
for B in $GCS; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "https://$B" 2>/dev/null)
  if [ "$R" = "200" ]; then
    LISTING=$(curl -s --max-time 8 "https://$B" 2>/dev/null | head -c 500)
    if echo "$LISTING" | grep -q "<ListBucketResult"; then
      emit "{\"title\":\"Open GCS bucket: $B\",\"severity\":\"critical\",\"description\":\"Google Cloud Storage bucket $B is publicly listable.\",\"remediation\":\"Set uniform bucket-level access. Use signed URLs.\",\"cweId\":\"CWE-732\",\"owaspCategory\":\"A01:2025-Broken Access Control\"}"
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
