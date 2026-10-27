#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        CI/CD Pipeline Exposure (Jenkins/GitLab/GitHub Actions/Drone)
# Description: Detects exposed CI/CD consoles and build systems
# Severity:    CRITICAL
# Category:    Information & Sensitive Data Disclosure
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: CI/CD Pipeline Exposure (Jenkins/GitLab/GitHub Actions/Drone)\033[0m"
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
PATHS="jenkins jenkins/login jenkins/script jenkins/credentials gitlab gitlab/users/sign_in gitlab/api/v4/version drone ci cd bamboo dashboard login.html buildbot teamcity app/rest/server circleci"
for P in $PATHS; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ]; then
    BODY=$(curl -s --max-time 8 "$T/$P" 2>/dev/null | head -c 800)
    if echo "$BODY" | grep -qi "jenkins\|gitlab\|drone\|bamboo\|teamcity\|buildbot\|sign in"; then
      SEV="high"
      case "$P" in *script*|*credentials*) SEV="critical";; esac
      emit "{\"title\":\"CI/CD system exposed: /$P\",\"severity\":\"$SEV\",\"description\":\"CI/CD interface /$P is accessible. Compromise gives source code access, build pipeline manipulation, and secrets theft.\",\"remediation\":\"Restrict CI/CD systems to VPN/internal networks. Enforce SSO with MFA.\",\"cweId\":\"CWE-798\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
