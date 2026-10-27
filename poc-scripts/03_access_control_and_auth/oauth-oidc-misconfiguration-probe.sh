#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        OAuth/OIDC Misconfiguration Probe
# Description: Tests redirect_uri validation and state parameter on OAuth flows
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: OAuth/OIDC Misconfiguration Probe\033[0m"
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
# find OAuth endpoints
PATHS="oauth/authorize oauth2/authorize .well-known/openid-configuration auth/authorize connect/authorize signin/oauth"
for P in $PATHS; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ] || [ "$R" = "302" ]; then
    # test open redirect in redirect_uri
    R2=$(curl -s -o /dev/null -w "%{redirect_url}" --max-time 10 "$T/$P?client_id=test&redirect_uri=https://evil.example.com/callback&response_type=code&state=" 2>/dev/null)
    if echo "$R2" | grep -q "evil.example.com"; then
      emit "{\"title\":\"OAuth redirect_uri not validated: /$P\",\"severity\":\"high\",\"description\":\"OAuth authorization endpoint /$P accepts arbitrary redirect_uri. Authorization codes can be stolen.\",\"remediation\":\"Strictly whitelist redirect_uri values. Exact match only, no wildcard.\",\"cweId\":\"CWE-601\",\"owaspCategory\":\"A07:2025-Identification and Authentication Failures\"}"
    fi
    # state parameter check
    R3=$(curl -s -o /dev/null -w "%{redirect_url}" --max-time 10 "$T/$P?client_id=test&redirect_uri=https://evil.example.com&response_type=code" 2>/dev/null)
    if [ -n "$R3" ] && ! echo "$R3" | grep -q "state="; then
      emit "{\"title\":\"OAuth state parameter missing: /$P\",\"severity\":\"medium\",\"description\":\"OAuth flow at /$P does not include state parameter — CSRF on authorization flow possible.\",\"remediation\":\"Generate random state parameter and validate on callback.\",\"cweId\":\"CWE-352\",\"owaspCategory\":\"A07:2025-Identification and Authentication Failures\"}"
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
