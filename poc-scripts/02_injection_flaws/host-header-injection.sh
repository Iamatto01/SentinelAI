#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Host Header Injection
# Description: Tests for host header injection — cache poisoning, password reset poisoning
# Severity:    MEDIUM
# Category:    Injection Flaws (SQLi, XSS, Command, SSTI, XXE)
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Host Header Injection\033[0m"
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
HOST=$(echo "$T" | sed 's|https\?://||' | cut -d/ -f1)
# Test 1: arbitrary host
R=$(curl -s --max-time 10 -H "Host: evil-host-injection.com" "$T" 2>/dev/null | head -c 3000)
if echo "$R" | grep -qi "evil-host-injection"; then
  emit "{\"title\":\"Host header injection — reflected in response\",\"severity\":\"high\",\"description\":\"Arbitrary Host header value is reflected in page content. Cache poisoning and password reset poisoning possible.\",\"remediation\":\"Validate Host header against allowlist. Use absolute URLs in emails.\",\"cweId\":\"CWE-644\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi
# Test 2: X-Forwarded-Host
R=$(curl -s --max-time 10 -H "X-Forwarded-Host: evil-fwd-host.com" "$T" 2>/dev/null | head -c 3000)
if echo "$R" | grep -qi "evil-fwd-host"; then
  emit "{\"title\":\"X-Forwarded-Host injection\",\"severity\":\"high\",\"description\":\"X-Forwarded-Host header is reflected in response. Cache poisoning possible.\",\"remediation\":\"Strip untrusted X-Forwarded-* headers at the proxy. Validate host.\",\"cweId\":\"CWE-644\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
