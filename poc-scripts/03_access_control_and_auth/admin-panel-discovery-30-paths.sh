#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Admin Panel Discovery (30 paths)
# Description: Batch-checks 30 common admin panel URLs
# Severity:    INFO
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Admin Panel Discovery (30 paths)\033[0m"
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
PATHS="admin admin/ admin/login admin/login.php admin/login.html adminpanel admin-panel administrator administrator/login cpanel dashboard wp-admin wp-login.php phpmyadmin pma myadmin mysql adminer manager management controlpanel control-panel user/login panel backoffice back-office secure admin area admin/index.php admin/home admin/dashboard system admin1 admin2 adm login-admin adminarea adminarea/login"
for P in $PATHS; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 6 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ] || [ "$R" = "401" ]; then
    SEV=$([ "$R" = "200" ] && echo "medium" || echo "info")
    emit "{\"title\":\"Admin panel discovered: /$P (HTTP $R)\",\"severity\":\"$SEV\",\"description\":\"Administrative interface found at /$P returning HTTP $R. Exposed admin surfaces increase attack surface for credential attacks.\",\"remediation\":\"Restrict admin panels to internal networks or VPN. Implement IP allowlisting and MFA.\",\"cweId\":\"CWE-798\",\"owaspCategory\":\"A07:2025-Identification and Authentication Failures\"}"
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
