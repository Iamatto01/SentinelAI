#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        User Enumeration via Login Response
# Description: Differential response analysis on login endpoints
# Severity:    MEDIUM
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: User Enumeration via Login Response\033[0m"
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
for EP in "login" "api/login" "api/auth/login" "api/v1/login" "signin" "api/signin" "auth"; do
  R1=$(curl -s -X POST -H "Content-Type: application/json" -d '{"username":"admin","password":"wrongpassword123"}' --max-time 10 "$T/$EP" 2>/dev/null)
  R2=$(curl -s -X POST -H "Content-Type: application/json" -d '{"username":"nonexistentuserxyz123","password":"wrongpassword123"}' --max-time 10 "$T/$EP" 2>/dev/null)
  if [ -n "$R1" ] && [ "$R1" != "$R2" ]; then
    # check for specific differential messages
    if echo "$R1$R2" | grep -qi "user not found\|invalid username\|no such user\|account does not exist\|email not found"; then
      emit "{\"title\":\"User enumeration via login error: /$EP\",\"severity\":\"medium\",\"description\":\"Login endpoint /$EP returns different errors for invalid username vs invalid password. Attackers can enumerate valid usernames.\",\"remediation\":\"Return generic 'Invalid credentials' for both cases.\",\"cweId\":\"CWE-204\",\"owaspCategory\":\"A07:2025-Identification and Authentication Failures\"}"
      break
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
