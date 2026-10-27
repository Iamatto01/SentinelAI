#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Subdomain Takeover Indicators
# Description: Checks CNAME records for takeover-vulnerable services
# Severity:    HIGH
# Category:    Network, Cloud & Infrastructure Security
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Subdomain Takeover Indicators\033[0m"
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
if command -v dig >/dev/null || command -v nslookup >/dev/null; then
  if command -v dig >/dev/null; then
    CN=$(dig +short CNAME "$HOST" 2>/dev/null | head -1)
  else
    CN=$(nslookup -type=CNAME "$HOST" 2>/dev/null | grep "canonical name" | sed 's/.*= //')
  fi
  if [ -n "$CN" ]; then
    # check for known takeover-vulnerable CNAMEs
    case "$CN" in
      *.cloudfront.net)
        R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "https://$HOST" 2>/dev/null)
        if echo "$R" | grep -q "404\|Bad request"; then
          emit "{\"title\":\"Potential CloudFront subdomain takeover\",\"severity\":\"high\",\"description\":\"CNAME points to $CN but origin returns error. If the CloudFront distribution is deleted, domain can be claimed.\",\"remediation\":\"Remove stale CNAME records. Verify all DNS entries point to active services.\",\"cweId\":\"CWE-1392\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
        fi
        ;;
      *.herokuapp.com|*.herokudns.com)
        R=$(curl -s --max-time 10 "https://$HOST" 2>/dev/null | head -c 500)
        if echo "$R" | grep -qi "no such app\|heroku \| nothing here"; then
          emit "{\"title\":\"Potential Heroku subdomain takeover\",\"severity\":\"high\",\"description\":\"CNAME points to $CN which shows 'no such app'. Domain can be claimed by creating a Heroku app with this name.\",\"remediation\":\"Remove stale CNAME record.\",\"cweId\":\"CWE-1392\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
        fi
        ;;
      *.github.io)
        R=$(curl -s --max-time 10 "https://$HOST" 2>/dev/null | head -c 500)
        if echo "$R" | grep -qi "404\|there isn't a github pages site here"; then
          emit "{\"title\":\"Potential GitHub Pages subdomain takeover\",\"severity\":\"high\",\"description\":\"CNAME points to $CN but no GitHub Pages site exists. Can be claimed by creating a repo with matching name.\",\"remediation\":\"Remove stale CNAME record.\",\"cweId\":\"CWE-1392\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
        fi
        ;;
      *.azurewebsites.net)
        R=$(curl -s --max-time 10 "https://$HOST" 2>/dev/null | head -c 500)
        if echo "$R" | grep -qi "404 web site not found"; then
          emit "{\"title\":\"Potential Azure subdomain takeover\",\"severity\":\"high\",\"description\":\"CNAME points to $CN which returns 404. Azure App Service domain can be claimed.\",\"remediation\":\"Remove stale CNAME record.\",\"cweId\":\"CWE-1392\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
        fi
        ;;
    esac
  fi
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
