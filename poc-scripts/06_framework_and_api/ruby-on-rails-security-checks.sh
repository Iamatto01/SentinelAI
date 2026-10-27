#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Ruby on Rails Security Checks
# Description: Detects Rails footprints, exposed routes, and console
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Ruby on Rails Security Checks\033[0m"
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
# Rails console/routes exposure
PATHS="rails/info routes rails/routes console console/session new_user_session users/sign_in sidekiq resque admin/login active_admin"
for P in $PATHS; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ]; then
    BODY=$(curl -s --max-time 8 "$T/$P" 2>/dev/null | head -c 2000)
    if echo "$BODY" | grep -qi "rails\|action_controller\|active_admin\|sidekiq\|resque"; then
      SEV="medium"
      case "$P" in console*|sidekiq|resque) SEV="high";; esac
      DETAIL="Reveals application routes and structure."
      if [ "$SEV" = "high" ]; then DETAIL="Console or background job UI allows code execution!"; fi
      emit "{\"title\":\"Rails endpoint exposed: /$P\",\"severity\":\"$SEV\",\"description\":\"Ruby on Rails endpoint /$P is accessible. $DETAIL\",\"remediation\":\"Restrict Rails console and admin UI. Disable routes endpoint in production.\",\"cweId\":\"CWE-200\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
    fi
  fi
done
# CSRF token check
H=$(curl -s -I --max-time 10 "$T" 2>/dev/null)
if echo "$H" | grep -qi "x-request-id\|x-runtime"; then
  if ! echo "$H" | grep -qi "x-frame-options\|content-security-policy"; then
    emit "{\"title\":\"Rails app missing clickjacking protection\",\"severity\":\"low\",\"description\":\"Rails detected (X-Request-Id/X-Runtime headers) but no X-Frame-Options or CSP header.\",\"remediation\":\"Rails sets X-Frame-Options by default — verify config.action_dispatch.default_headers.\",\"cweId\":\"CWE-1021\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
