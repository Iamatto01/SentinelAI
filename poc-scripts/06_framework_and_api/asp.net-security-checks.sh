#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        ASP.NET Security Checks
# Description: Detects ASP.NET debug traces, viewstate, and machine key leaks
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: ASP.NET Security Checks\033[0m"
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
# Trace.axd exposure
R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/trace.axd" 2>/dev/null)
if [ "$R" = "200" ]; then
  BODY=$(curl -s --max-time 8 "$T/trace.axd" 2>/dev/null | head -c 2000)
  if echo "$BODY" | grep -qi "application trace\|request details"; then
    emit "{\"title\":\"ASP.NET trace exposed: /trace.axd\",\"severity\":\"high\",\"description\":\"ASP.NET tracing is enabled and accessible. Reveals session IDs, request data, and internal paths.\",\"remediation\":\"Set <trace enabled=false> in web.config. Remove trace.axd handler.\",\"cweId\":\"CWE-200\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
fi
# elmah.axd
R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/elmah.axd" 2>/dev/null)
if [ "$R" = "200" ]; then
  emit "{\"title\":\"ELMAH error log exposed: /elmah.axd\",\"severity\":\"high\",\"description\":\"ELMAH error logging page is accessible. Reveals stack traces, cookies, and form data.\",\"remediation\":\"Restrict elmah.axd to authorized users or remove in production.\",\"cweId\":\"CWE-200\",\"owaspCategory\":\"A09:2025-Security Logging and Monitoring Failures\"}"
fi
# WebResource.axd info
R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/WebResource.axd?d=test" 2>/dev/null)
if [ "$R" = "500" ]; then
  emit "{\"title\":\"ASP.NET WebResource.axd responds with error\",\"severity\":\"info\",\"description\":\"WebResource.axd exists (500 on invalid param). Old ASP.NET versions have ViewState/MachineKey exploits (e.g., CVE-2017-9822).\",\"remediation\":\"Update .NET Framework. Validate ViewState. Use ASP.NET validation key rotation.\",\"cweId\":\"CWE-200\",\"owaspCategory\":\"A06:2025-Vulnerable and Outdated Components\"}"
fi
# machine key in web.config
R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/web.config" 2>/dev/null)
if [ "$R" = "200" ]; then
  BODY=$(curl -s --max-time 8 "$T/web.config" 2>/dev/null | head -c 3000)
  if echo "$BODY" | grep -qi "machineKey\|connectionString\|password"; then
    emit "{\"title\":\"web.config exposed with secrets\",\"severity\":\"critical\",\"description\":\"web.config is readable and contains machineKey or connectionString — full RCE via ViewState deserialization possible.\",\"remediation\":\"Block web.config access. Rotate machineKey and DB credentials immediately.\",\"cweId\":\"CWE-538\",\"owaspCategory\":\"A02:2025-Cryptographic Failures\"}"
  fi
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
