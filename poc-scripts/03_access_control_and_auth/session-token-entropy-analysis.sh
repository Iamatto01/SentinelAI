#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Session Token Entropy Analysis
# Description: Collects session cookies and checks for predictability
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Session Token Entropy Analysis\033[0m"
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
# collect 5 session cookies
declare -a COOKIES
for I in 1 2 3 4 5; do
  C=$(curl -s -I --max-time 10 "$T" 2>/dev/null | grep -i "set-cookie" | head -1 | sed 's/.*: //' | cut -d';' -f1)
  COOKIES[$I]="$C"
done
# check uniqueness
UNIQ=$(printf '%s\n' "${COOKIES[@]}" | sort -u | wc -l)
if [ "$UNIQ" -lt 5 ] && [ -n "${COOKIES[1]}" ]; then
  emit "{\"title\":\"Session tokens not unique\",\"severity\":\"critical\",\"description\":\"Only $UNIQ unique session tokens from 5 requests. Session fixation or token reuse possible.\",\"remediation\":\"Generate cryptographically random session IDs (128-bit+). Regenerate on login.\",\"cweId\":\"CWE-331\",\"owaspCategory\":\"A02:2025-Cryptographic Failures\"}"
fi
# check token length (short = weak)
if [ -n "${COOKIES[1]}" ]; then
  VAL=$(echo "${COOKIES[1]}" | cut -d= -f2)
  LEN=${#VAL}
  if [ $LEN -lt 16 ] && [ $LEN -gt 0 ]; then
    emit "{\"title\":\"Short session token ($LEN chars)\",\"severity\":\"medium\",\"description\":\"Session token is only $LEN characters — brute-forceable.\",\"remediation\":\"Use 128-bit minimum session tokens from CSPRNG.\",\"cweId\":\"CWE-326\",\"owaspCategory\":\"A02:2025-Cryptographic Failures\"}"
  fi
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
