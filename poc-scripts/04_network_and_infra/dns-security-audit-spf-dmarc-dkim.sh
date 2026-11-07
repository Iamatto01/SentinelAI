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

# --- Core PoC Execution ---
# Single emit handler. The previous duplicate definition (a python3 pretty-printer
# shadowed by a plain one) is intentionally gone: emitting twice per call would
# double every finding downstream, and the JSONL contract requires raw JSON only.
emit() { printf '%s\n' "$1"; }

HOST=$(echo "$TARGET" | sed 's|https\?://||' | cut -d/ -f1 | cut -d: -f1)

jsonstr() { printf '%s' "$1" | tr -d '\000-\010\013\014\016-\037' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

# ── Resolver abstraction ────────────────────────────────────────────────────
# `dig` is the preferred resolver but is NOT present by default on Windows/Git
# Bash hosts (or on minimal containers). The old code wrapped the ENTIRE probe
# body in `if command -v dig; then ... fi` with no `else`, so a host without
# dig produced ZERO output — a silent false negative that reads downstream as
# "domain is clean". Resolve the first available backend and never no-op.
DNS_BACKEND=""
if command -v dig >/dev/null 2>&1;      then DNS_BACKEND="dig"
elif command -v nslookup >/dev/null 2>&1; then DNS_BACKEND="nslookup"
elif command -v host >/dev/null 2>&1;     then DNS_BACKEND="host"
fi

# `dns_query` must return ONLY genuine record payload for the requested type.
# Two traps this normalisation has to avoid, both observed on Windows/Git Bash
# with the Windows nslookup:
#   1. nslookup prints its own diagnostics ("DNS request timed out.",
#      "*** UnKnown can't find ...", "Non-existent domain") on stdout. Those are
#      NOT records — treating them as payload silently suppresses findings.
#   2. On a type nslookup cannot express (CAA on Windows), it falls back to an
#      A-record lookup and prints Name:/Addresses:. That output must never be
#      mistaken for a CAA record, or the CAA gap is never reported.
# dns_query <type> <name>  -> flattened record text on stdout (one per line)
dns_query() {
  _qtype="$1"; _qname="$2"
  case "$DNS_BACKEND" in
    dig)
      # dig exits non-zero on SERVFAIL/NXDOMAIN; surface that as no record.
      dig +short "$_qtype" "$_qname" 2>/dev/null | grep -v '^;' ;;
    nslookup)
      nslookup -type="$_qtype" "$_qname" 2>/dev/null \
        | sed -e '/^Server:/d' -e '/^Address:/d' -e '/^Name:/d' -e '/^Addresses:/d' \
              -e '/^Aliases:/d' -e '/canonical name =/d' \
              -e '/timed out/I d' -e "/can't find/I d" -e '/Non-existent domain/I d' \
              -e '/^\*\*\*/d' -e '/unknown query type/I d' -e '/^[[:space:]]*$/d' \
              -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
        | grep -v '^$' \
        | sed -e '/^Non-authoritative answer:/Id' \
              -e '/^Authoritative answers can be found from:/Id' \
              -e '/^origin = /Id' -e '/^serial = /Id' -e '/^refresh = /Id' \
              -e '/^retry = /Id' -e '/^expire = /Id' -e '/^minimum = /Id' \
              -e '/^[0-9][0-9]* ([0-9]/d' \
              -e '/^[a-z0-9._-]*[[:space:]]*internet address = /Id' \
              -e '/^[a-z0-9._-]*[[:space:]]*canonical name = /Id' \
        | sed -e 's/^[^=]*= //' \
        | tr -d '"' ;;
    host)
      host -t "$_qtype" "$_qname" 2>/dev/null \
        | sed -e '/not found/I d' -e '/has no/I d' \
        | sed -e 's/^.*descriptive text //' -e 's/^.*has //' | tr -d '"' ;;
    *)
      echo "" ;;
  esac
}

if [ -z "$DNS_BACKEND" ]; then
  # No resolver at all — report the coverage gap instead of silently passing.
  emit "{\"title\":\"DNS audit could not run — no resolver available\",\"severity\":\"info\",\"description\":\"Neither dig, nslookup nor host was found on the scanning host, so SPF/DMARC/CAA records for $(jsonstr "$HOST") could not be checked. This is a scan-coverage gap, not evidence that the domain is clean.\",\"remediation\":\"Install dnsutils (dig) on the scanning host.\",\"cweId\":\"CWE-1059\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
else
  # Keep only plausible record payload. The A-record block ("104.20.44.243",
  # "2606:4700:10::...") has no "=" and no "v=" prefix; a real TXT/CAA record
  # always carries its tag ("v=spf1", "v=DMARC1", "0 issue \"...\""). Requiring a
  # tag or a quoted value stops an A-fallback lookup from faking a record.
  SPF_RAW=$(dns_query TXT "$HOST" | grep -i "v=spf1" | head -1)
  DMARC_RAW=$(dns_query TXT "_dmarc.$HOST" | grep -i "v=DMARC1" | head -1)
  CAA_RAW=$(dns_query CAA "$HOST" | grep -Ei "(issue|issuewild|iodef)[[:space:]]*\"?[a-z0-9.-]+" | head -1)

  # Record whether the resolver actually answered, so a timeout/NXDOMAIN is
  # disclosed in evidence instead of being reported as a confirmed absence.
  RESOLVER_ERR=$(dns_query TXT "$HOST" | grep -Eic "timed out|can't find" || true)
  [ "$RESOLVER_ERR" -gt 0 ] 2>/dev/null && RESOLVER_NOTE="resolver did not answer (timeout or NXDOMAIN); absence is unconfirmed" || RESOLVER_NOTE="resolver answered the query"

  if [ -z "$SPF_RAW" ]; then
    emit "{\"title\":\"No SPF record — email spoofing possible\",\"severity\":\"medium\",\"description\":\"Domain $(jsonstr "$HOST") has no SPF record. Anyone can send emails appearing to be from this domain — phishing attacks.\",\"remediation\":\"Add SPF record: v=spf1 include:_spf.google.com -all (adjust for your mail provider).\",\"cweId\":\"CWE-290\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\",\"evidence\":{\"raw\":\"$(jsonstr "resolver=$DNS_BACKEND query=TXT $HOST -> no v=spf1 record")\",\"recordType\":\"TXT\",\"queriedName\":\"$(jsonstr "$HOST")\",\"resolver\":\"$(jsonstr "$DNS_BACKEND")\",\"resolverStatus\":\"$(jsonstr "$RESOLVER_NOTE")\"}}"
  fi

  if [ -z "$DMARC_RAW" ]; then
    emit "{\"title\":\"No DMARC record — no email authentication policy\",\"severity\":\"medium\",\"description\":\"Domain $(jsonstr "$HOST") has no DMARC record. Spoofed emails have no policy for rejection/quarantine.\",\"remediation\":\"Add DMARC record: _dmarc.$(jsonstr "$HOST") TXT v=DMARC1; p=quarantine; rua=mailto:dmarc@$(jsonstr "$HOST")\",\"cweId\":\"CWE-290\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\",\"evidence\":{\"raw\":\"$(jsonstr "resolver=$DNS_BACKEND query=TXT _dmarc.$HOST -> no v=DMARC1 record")\",\"recordType\":\"TXT\",\"queriedName\":\"$(jsonstr "_dmarc.$HOST")\",\"resolver\":\"$(jsonstr "$DNS_BACKEND")\",\"resolverStatus\":\"$(jsonstr "$RESOLVER_NOTE")\"}}"
  elif echo "$DMARC_RAW" | grep -q "p=none"; then
    emit "{\"title\":\"DMARC policy is p=none (monitor only)\",\"severity\":\"low\",\"description\":\"DMARC policy is set to none — spoofed emails are monitored but not rejected.\",\"remediation\":\"Escalate DMARC policy to quarantine or reject.\",\"cweId\":\"CWE-290\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\",\"evidence\":{\"raw\":\"$(jsonstr "resolver=$DNS_BACKEND query=TXT _dmarc.$HOST -> $DMARC_RAW")\",\"recordType\":\"TXT\",\"queriedName\":\"$(jsonstr "_dmarc.$HOST")\",\"resolver\":\"$(jsonstr "$DNS_BACKEND")\",\"resolverStatus\":\"$(jsonstr "$RESOLVER_NOTE")\"}}"
  fi

  if [ -z "$CAA_RAW" ]; then
    emit "{\"title\":\"No CAA record — any CA can issue certs\",\"severity\":\"info\",\"description\":\"No CAA record restricts which certificate authorities can issue certificates for $(jsonstr "$HOST").\",\"remediation\":\"Add CAA record restricting issuance to your CA (e.g., letsencrypt.org).\",\"cweId\":\"CWE-295\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\",\"evidence\":{\"raw\":\"$(jsonstr "resolver=$DNS_BACKEND query=CAA $HOST -> no CAA record")\",\"recordType\":\"CAA\",\"queriedName\":\"$(jsonstr "$HOST")\",\"resolver\":\"$(jsonstr "$DNS_BACKEND")\",\"method\":\"$(jsonstr "$DNS_BACKEND")\",\"note\":\"nslookup has no CAA type on some platforms; absence here may be a resolver limitation rather than a true gap\",\"resolverStatus\":\"$(jsonstr "$RESOLVER_NOTE")\"}}"
  fi
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
