#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        CSP Deep Analysis
# Description: Parses CSP header for unsafe directives and bypass vectors
# Severity:    MEDIUM
# Category:    Web Server & HTTP Misconfigurations
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: CSP Deep Analysis\033[0m"
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
CSP=$(curl -s -I --max-time 10 "$T" 2>/dev/null | grep -i "content-security-policy" | tr -d '\r' | sed 's/.*: //i')
if [ -n "$CSP" ]; then
  if echo "$CSP" | grep -q "unsafe-inline"; then
    emit "{\"title\":\"CSP allows unsafe-inline scripts\",\"severity\":\"medium\",\"description\":\"Content-Security-Policy contains unsafe-inline — inline scripts and event handlers execute. XSS protection significantly weakened.\",\"remediation\":\"Remove unsafe-inline. Use nonces or hashes for inline scripts.\",\"cweId\":\"CWE-79\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
  if echo "$CSP" | grep -q "unsafe-eval"; then
    emit "{\"title\":\"CSP allows unsafe-eval\",\"severity\":\"medium\",\"description\":\"Content-Security-Policy contains unsafe-eval — eval() and similar execute. XSS payload execution easier.\",\"remediation\":\"Remove unsafe-eval. Refactor code to avoid eval.\",\"cweId\":\"CWE-79\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
  if echo "$CSP" | grep -qE "script-src[^;]*(\*|http:)"; then
    emit "{\"title\":\"CSP script-src allows wildcard or HTTP\",\"severity\":\"medium\",\"description\":\"CSP script-src allows * or http: sources — external script injection possible.\",\"remediation\":\"Restrict script-src to specific trusted HTTPS origins.\",\"cweId\":\"CWE-79\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
  if ! echo "$CSP" | grep -q "object-src"; then
    emit "{\"title\":\"CSP missing object-src directive\",\"severity\":\"low\",\"description\":\"CSP does not restrict object-src — plugin content (Flash/Java) can load.\",\"remediation\":\"Add object-src 'none' to CSP.\",\"cweId\":\"CWE-79\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
  if ! echo "$CSP" | grep -q "base-uri"; then
    emit "{\"title\":\"CSP missing base-uri directive\",\"severity\":\"low\",\"description\":\"CSP does not restrict base-uri — <base> tag injection can hijack relative URLs.\",\"remediation\":\"Add base-uri 'self' to CSP.\",\"cweId\":\"CWE-79\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
