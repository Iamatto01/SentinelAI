#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Laravel Security Audit (8 checks)
# Description: .env exposure, APP_KEY leak, debug mode, storage symlink, telescope
# Severity:    HIGH
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Laravel Security Audit (8 checks)\033[0m"
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
# .env (Laravel specific paths)
for P in ".env" "../.env" ".env.example"; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ]; then
    BODY=$(curl -s --max-time 8 "$T/$P" 2>/dev/null | head -c 3000)
    if echo "$BODY" | grep -q "APP_KEY"; then
      emit "{\"title\":\"Laravel .env file exposed\",\"severity\":\"critical\",\"description\":\"Laravel environment file is readable — APP_KEY, database credentials, mail credentials all exposed. RCE possible via APP_KEY decryption.\",\"remediation\":\"Move .env outside web root. Block dotfile access in nginx/apache.\",\"cweId\":\"CWE-548\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
    fi
  fi
done
# Debug mode (Whoops)
BODY=$(curl -s --max-time 10 "$T/_ignition/health-check" 2>/dev/null | head -c 500)
R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$T/_ignition/health-check" 2>/dev/null)
if [ "$R" = "200" ]; then
  emit "{\"title\":\"Laravel Ignition debug endpoint exposed\",\"severity\":\"critical\",\"description\":\"Ignition debug endpoint is accessible. CVE-2021-3129 — unauthenticated RCE via Ignition log file manipulation.\",\"remediation\":\"Set APP_DEBUG=false. Update ignition package.\",\"cweId\":\"CWE-489\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi
# Telescope
R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/telescope" 2>/dev/null)
if [ "$R" = "200" ]; then
  emit "{\"title\":\"Laravel Telescope exposed\",\"severity\":\"high\",\"description\":\"Laravel Telescope debug tool is publicly accessible — exposes requests, queries, jobs, logs.\",\"remediation\":\"Restrict Telescope to local/dev environments only.\",\"cweId\":\"CWE-489\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi
# Storage symlink
R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/storage/logs/laravel.log" 2>/dev/null)
if [ "$R" = "200" ]; then
  emit "{\"title\":\"Lavel log file exposed\",\"severity\":\"high\",\"description\":\"storage/logs/laravel.log is readable — contains stack traces, environment data, possibly credentials.\",\"remediation\":\"Restrict storage directory access. Use daily logs and rotate.\",\"cweId\":\"CWE-532\",\"owaspCategory\":\"A09:2025-Security Logging and Monitoring Failures\"}"
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
