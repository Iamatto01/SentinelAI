#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Spring Boot Actuator Full Audit
# Description: Deep actuator scan — env, heapdump, mappings, beans, trace endpoints
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Spring Boot Actuator Full Audit\033[0m"
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
ACTUATORS="actuator actuator/env actuator/heapdump actuator/mappings actuator/beans actuator/configprops actuator/trace actuator/httptrace actuator/auditevents actuator/sessions actuator/threaddump actuator/loggers actuator/health actuator/info actuator/metrics actuator/gateway/routes manage/actuator management/actuator admin/actuator"
for A in $ACTUATORS; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$A" 2>/dev/null)
  if [ "$R" = "200" ]; then
    BODY=$(curl -s --max-time 8 "$T/$A" 2>/dev/null | head -c 300)
    if echo "$BODY" | grep -q "{\|\"_links\""; then
      SEV="high"
      case "$A" in *env*|*heapdump*|*trace*|*loggers*|*configprops*) SEV="critical";; esac
      DETAIL="Reveals application internals."
      case "$A" in *env*) DETAIL="Exposes environment variables including credentials.";; *heapdump*) DETAIL="Heap dump contains in-memory secrets and session data.";; *trace*|*httptrace*) DETAIL="Reveals full request/response history including headers and tokens.";; *loggers*) DETAIL="Loggers can be modified to leak sensitive data.";; *configprops*) DETAIL="Exposes configuration properties including database settings.";; esac
      emit "{\"title\":\"Spring Boot actuator exposed: /$A\",\"severity\":\"$SEV\",\"description\":\"Spring Boot actuator endpoint /$A is publicly accessible. $DETAIL\",\"remediation\":\"Restrict actuator endpoints to internal networks. Set management.endpoints.web.exposure.include=health only.\",\"cweId\":\"CWE-200\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
