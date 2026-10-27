#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Email Address Harvesting from Pages
# Description: Extracts email patterns from public pages for phishing assessment
# Severity:    INFO
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Email Address Harvesting from Pages\033[0m"
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
EMAILS=$(curl -s -L --max-time 15 "$T" 2>/dev/null | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sort -u | head -10)
# also check contact/about pages
for P in "contact" "about" "team" "impressum"; do
  MORE=$(curl -s -L --max-time 10 "$T/$P" 2>/dev/null | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | head -5)
  EMAILS="$EMAILS\n$MORE"
done
UNIQ=$(echo -e "$EMAILS" | sort -u | grep -v '^$' | head -10)
COUNT=$(echo "$UNIQ" | grep -c .)
if [ "$COUNT" -gt 0 ]; then
  LIST=$(echo "$UNIQ" | tr '\n' ',' | sed 's/,$//')
  emit "{\"title\":\"$COUNT email addresses harvested\",\"severity\":\"info\",\"description\":\"Public pages expose $COUNT email addresses: $LIST. Useful for spear-phishing assessment and credential stuffing target lists.\",\"remediation\":\"Minimize public email exposure. Use contact forms instead.\",\"cweId\":\"CWE-200\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
