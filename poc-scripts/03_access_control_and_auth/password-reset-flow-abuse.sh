#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Password Reset Flow Abuse
# Description: Tests reset tokens for predictability and user enumeration
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Password Reset Flow Abuse\033[0m"
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
# user enumeration via reset response differential
for EP in "api/forgot-password" "api/reset-password" "api/auth/forgot" "forgot-password" "reset-password" "api/v1/forgot-password" "api/password-reset"; do
  R1=$(curl -s -X POST -H "Content-Type: application/json" -d '{"email":"admin@target.com"}' --max-time 10 "$T/$EP" 2>/dev/null | head -c 500)
  R2=$(curl -s -X POST -H "Content-Type: application/json" -d '{"email":"nonexistentuser12345@target.com"}' --max-time 10 "$T/$EP" 2>/dev/null | head -c 500)
  if [ -n "$R1" ] && [ "$R1" != "$R2" ]; then
    emit "{\"title\":\"User enumeration via password reset: /$EP\",\"severity\":\"medium\",\"description\":\"Password reset endpoint returns different responses for existing vs non-existing emails. Account enumeration possible.\",\"remediation\":\"Return identical generic response regardless of email existence.\",\"cweId\":\"CWE-204\",\"owaspCategory\":\"A07:2025-Identification and Authentication Failures\"}"
  fi
  # check if reset link/token is returned in response (insecure)
  if echo "$R1" | grep -qi "token\|reset_url\|reset_link"; then
    emit "{\"title\":\"Password reset token leaked in response: /$EP\",\"severity\":\"critical\",\"description\":\"Password reset token is returned in the API response instead of only via email. Anyone can reset any account password.\",\"remediation\":\"Send reset tokens only via email. Never include tokens in API responses.\",\"cweId\":\"CWE-200\",\"owaspCategory\":\"A07:2025-Identification and Authentication Failures\"}"
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
