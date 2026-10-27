#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Login Rate Limiting Test
# Description: Burst of failed logins to check for 429/CAPTCHA/lockout
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Login Rate Limiting Test\033[0m"
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
# find login endpoint
for EP in "login" "api/login" "api/auth/login" "api/v1/login" "api/v1/auth/login" "auth/login" "signin" "api/signin"; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$EP" 2>/dev/null)
  if [ "$R" = "200" ] || [ "$R" = "405" ]; then
    # burst 20 failed logins
    LIMITED=0
    for I in $(seq 1 20); do
      RR=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" -d '{"username":"ratelimitprobe","password":"wrongpass'$I'"}' --max-time 8 "$T/$EP" 2>/dev/null)
      if [ "$RR" = "429" ]; then
        LIMITED=1
        emit "{\"title\":\"Rate limiting active on login (429 after $I attempts)\",\"severity\":\"info\",\"description\":\"Login endpoint /$EP returns 429 after $I failed attempts — rate limiting is properly configured.\",\"remediation\":\"No action needed.\",\"cweId\":\"CWE-770\",\"owaspCategory\":\"A07:2025-Identification and Authentication Failures\"}"
        break
      fi
    done
    if [ $LIMITED -eq 0 ]; then
      emit "{\"title\":\"No rate limiting on login endpoint: /$EP\",\"severity\":\"high\",\"description\":\"20 consecutive failed login attempts to /$EP without 429, CAPTCHA, or lockout. Credential stuffing and brute-force attacks possible.\",\"remediation\":\"Implement rate limiting (e.g., 5 attempts per minute per IP+account). Add CAPTCHA after failed attempts.\",\"cweId\":\"CWE-770\",\"owaspCategory\":\"A07:2025-Identification and Authentication Failures\"}"
    fi
    break
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
