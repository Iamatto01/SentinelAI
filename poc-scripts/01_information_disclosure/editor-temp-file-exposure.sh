#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Editor & Temp File Exposure
# Description: Checks for vim swap, emacs backup, nano temp files
# Severity:    MEDIUM
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Editor & Temp File Exposure\033[0m"
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
PATHS="index.php~ index.html~ .index.php.swp .index.html.swp index.php.swp index.html.swp #index.php# #index.html# index.php.orig index.html.orig index.php.old index.html.old index.php.copy index.php.bak.bak .bash_history .zsh_history .mysql_history .psql_history .viminfo .gitconfig .git-credentials"
for P in $PATHS; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ]; then
    SZ=$(curl -s --max-time 8 "$T/$P" 2>/dev/null | wc -c)
    if [ "$SZ" -gt 50 ]; then
      SEV="medium"
      case "$P" in .bash_history|.zsh_history|.mysql_history|.psql_history|.git-credentials) SEV="critical";; esac
      DETAIL="May contain source code or configuration."
      if [ "$SEV" = "critical" ]; then DETAIL="Shell/DB history files contain executed commands and possibly credentials!"; fi
      emit "{\"title\":\"Editor/temp file exposed: /$P\",\"severity\":\"$SEV\",\"description\":\"Temporary or editor backup file /$P is readable. $DETAIL\",\"remediation\":\"Remove temp files from web root. Add *~ *.swp #*# patterns to deployment exclusions.\",\"cweId\":\"CWE-548\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
