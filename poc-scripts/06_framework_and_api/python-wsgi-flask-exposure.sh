#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Python WSGI/Flask Exposure
# Description: Detects Flask debug console (Werkzeug), exposed .pyc, console pin attempts
# Severity:    CRITICAL
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Python WSGI/Flask Exposure\033[0m"
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
# Werkzeug debugger
BODY=$(curl -s --max-time 10 "$T/console" 2>/dev/null | head -c 1000)
if echo "$BODY" | grep -qi "werkzeug\|interactive console"; then
  emit "{\"title\":\"Werkzeug debug console exposed\",\"severity\":\"critical\",\"description\":\"Flask/Werkzeug interactive debug console is accessible at /console. If the debugger PIN can be bypassed or computed, this gives Remote Code Execution.\",\"remediation\":\"Disable debug mode. Never expose the Werkzeug debugger in production.\",\"cweId\":\"CWE-489\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi
# .pyc / .py exposure
for P in "app.pyc" "main.pyc" "app.py" "main.py" "wsgi.py" "asgi.py" "server.py"; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ]; then
    CT=$(curl -s -I --max-time 8 "$T/$P" 2>/dev/null | grep -i content-type)
    if ! echo "$CT" | grep -qi "text/html"; then
      emit "{\"title\":\"Python source/bytecode exposed: /$P\",\"severity\":\"high\",\"description\":\"Python file /$P is served raw. Source code and potential secrets are readable.\",\"remediation\":\"Serve only via WSGI. Remove .py/.pyc from web root.\",\"cweId\":\"CWE-548\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
