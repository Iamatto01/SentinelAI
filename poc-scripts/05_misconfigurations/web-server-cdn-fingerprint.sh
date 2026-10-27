#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Web Server & CDN Fingerprint
# Description: Identifies server software, CDN, and hosting from response headers
# Severity:    INFO
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Web Server & CDN Fingerprint\033[0m"
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
H=$(curl -s -I --max-time 10 "$T" 2>/dev/null)
SRV=$(echo "$H" | grep -i "^server:" | tr -d '\r' | sed 's/[Ss]erver: //')
CDN=""
echo "$H" | grep -qi "cf-ray\|cloudflare" && CDN="Cloudflare"
echo "$H" | grep -qi "x-amz-cf-id\|cloudfront" && CDN="CloudFront"
echo "$H" | grep -qi "x-fastly" && CDN="Fastly"
echo "$H" | grep -qi "x-served-by.*cache" && CDN="Fastly/Varnish"
echo "$H" | grep -qi "x-vercel-id" && CDN="Vercel"
echo "$H" | grep -qi "x-nf-request-id" && CDN="Netlify"
if [ -n "$SRV" ] || [ -n "$CDN" ]; then
  emit "{\"title\":\"Infrastructure fingerprint: $SRV $CDN\",\"severity\":\"info\",\"description\":\"Server: $SRV. CDN: $CDN. This informs which attack vectors apply (e.g., origin bypass for CDN-protected sites).\",\"remediation\":\"Informational finding for attack surface mapping.\",\"cweId\":\"CWE-200\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi
# check for origin IP leak
H2=$(curl -s -I --max-time 10 -H "Host: $(echo $T | sed 's|https\?://||' | cut -d/ -f1)" "http://$(echo $T | sed 's|https\?://||' | cut -d/ -f1)" 2>/dev/null)
if echo "$H2" | grep -qi "server:" && [ -n "$CDN" ]; then
  ORIGINSRV=$(echo "$H2" | grep -i "^server:" | tr -d '\r')
  if [ "$ORIGINSRV" != "$SRV" ]; then
    emit "{\"title\":\"Origin server fingerprint differs over HTTP\",\"severity\":\"low\",\"description\":\"HTTP response server header ($ORIGINSRV) differs from HTTPS ($SRV). Origin may be directly accessible, bypassing CDN protection.\",\"remediation\":\"Enforce HTTPS-only. Restrict origin server to accept CDN traffic only.\",\"cweId\":\"CWE-200\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
