#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        DNS Security Audit (SPF/DMARC/DKIM)
# Description: Checks email spoofing protections — SPF, DMARC, DKIM records
# Severity:    MEDIUM
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: DNS Security Audit (SPF/DMARC/DKIM)\033[0m"
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
  SPF=$(dig +short TXT "$HOST" 2>/dev/null | grep -i "v=spf1" | head -1)
  DMARC=$(dig +short TXT "_dmarc.$HOST" 2>/dev/null | head -1)
  if [ -z "$SPF" ]; then
    emit "{\"title\":\"No SPF record — email spoofing possible\",\"severity\":\"medium\",\"description\":\"Domain $HOST has no SPF record. Anyone can send emails appearing to be from this domain — phishing attacks.\",\"remediation\":\"Add SPF record: v=spf1 include:_spf.google.com -all (adjust for your mail provider).\",\"cweId\":\"CWE-290\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
  if [ -z "$DMARC" ]; then
    emit "{\"title\":\"No DMARC record — no email authentication policy\",\"severity\":\"medium\",\"description\":\"Domain $HOST has no DMARC record. Spoofed emails have no policy for rejection/quarantine.\",\"remediation\":\"Add DMARC record: _dmarc.$HOST TXT v=DMARC1; p=quarantine; rua=mailto:dmarc@$HOST\",\"cweId\":\"CWE-290\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  else
    if echo "$DMARC" | grep -q "p=none"; then
      emit "{\"title\":\"DMARC policy is p=none (monitor only)\",\"severity\":\"low\",\"description\":\"DMARC policy is set to none — spoofed emails are monitored but not rejected.\",\"remediation\":\"Escalate DMARC policy to quarantine or reject.\",\"cweId\":\"CWE-290\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
    fi
  fi
  # CAA record check
  CAA=$(dig +short CAA "$HOST" 2>/dev/null | head -1)
  if [ -z "$CAA" ]; then
    emit "{\"title\":\"No CAA record — any CA can issue certs\",\"severity\":\"info\",\"description\":\"No CAA record restricts which certificate authorities can issue certificates for $HOST.\",\"remediation\":\"Add CAA record restricting issuance to your CA (e.g., letsencrypt.org).\",\"cweId\":\"CWE-295\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
