#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Subdomain Takeover Check (CNAME-based)
# Description: Checks dangling CNAMEs pointing to takeover-able services
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Subdomain Takeover Check (CNAME-based)\033[0m"
echo -e "\033[1;34m[*] Target: $TARGET\033[0m"
echo ""

# Standard emit handler for standalone terminal execution
emit() {
  echo -e "\033[1;32m[+] VULNERABILITY CONFIRMED / FINDING EMITTED:\033[0m"
  echo "$1" | python3 -m json.tool 2>/dev/null || echo "    $1"
}

# --- Core PoC Execution ---
emit() { printf '%s\n' "$1"; }
HOST=$(echo "$TARGET" | sed 's|https\?://||' | cut -d/ -f1 | cut -d: -f1)
if command -v dig >/dev/null 2>&1; then
  # get subdomains from cert transparency
  SUBS=$(curl -s --max-time 20 "https://crt.sh/?q=%25.$HOST&output=json" 2>/dev/null | grep -o '"common_name":"[^"]*"' | cut -d'"' -f4 | sort -u | head -20)
  for SUB in $SUBS; do
    CNAME=$(dig +short CNAME "$SUB" 2>/dev/null | head -1)
    if [ -n "$CNAME" ]; then
      # check if CNAME target is a takeover-able service
      if echo "$CNAME" | grep -qi "herokuapp\|github.io\|azurewebsites\|cloudfront\|aws\|s3\|shopify\|fastly\|pantheon\|wordpress\|tumblr\|surge.sh\|bitbucket\|cargo\|readme.io\|zendesk\|freshdesk\|helpscout\"; then
        # check if target responds with NXDOMAIN or "no such app"
        R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "https://$SUB" 2>/dev/null)
        BODY=$(curl -s --max-time 8 "https://$SUB" 2>/dev/null | head -c 500)
        if [ "$R" = "404" ] || echo "$BODY" | grep -qi "no such app\|not found\|there isn't a github pages site here\|repository not found"; then
          emit "{\"title\":\"Potential subdomain takeover: $SUB\",\"severity\":\"high\",\"description\":\"Subdomain $SUB has dangling CNAME to $CNAME which returns 404/not-found. Claiming the target service enables full takeover.\",\"remediation\":\"Remove DNS records for decommissioned services. Monitor DNS for dangling CNAMEs.\",\"cweId\":\"CWE-1420\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
        fi
      fi
    fi
  done
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
