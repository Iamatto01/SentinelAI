#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Next.js/Nuxt.js SPA Security Checks
# Description: Detects build manifests, source maps, and API route exposure
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Next.js/Nuxt.js SPA Security Checks\033[0m"
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
# Next.js build manifest
PATHS="_next/static/chunks/webpack.js _next/static/chunks/main.js __nextjs_original-stack-frame _next/image nuxt.config.js .nuxt/config.json api/_next/api/health"
for P in $PATHS; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ]; then
    case "$P" in
      __nextjs_original-stack-frame)
        emit "{\"title\":\"Next.js dev overlay exposed\",\"severity\":\"high\",\"description\":\"Next.js development error overlay endpoint is accessible in what appears to be production. May leak stack traces and source code.\",\"remediation\":\"Set NODE_ENV=production. Disable dev overlay in production builds.\",\"cweId\":\"CWE-489\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
        ;;
      nuxt.config.js|.nuxt/config.json)
        BODY=$(curl -s --max-time 8 "$T/$P" 2>/dev/null | head -c 1000)
        if echo "$BODY" | grep -qi "apiKey\|secret\|token\|password"; then
          emit "{\"title\":\"Nuxt config exposed with potential secrets: /$P\",\"severity\":\"high\",\"description\":\"Nuxt configuration file /$P is readable and may contain API keys or secrets.\",\"remediation\":\"Never commit secrets to client-side configs. Use runtime config with server-only env vars.\",\"cweId\":\"CWE-538\",\"owaspCategory\":\"A02:2025-Cryptographic Failures\"}"
        fi
        ;;
    esac
  fi
done
# source map check
SM=$(curl -s --max-time 8 "$T/_next/static/chunks/webpack.js" 2>/dev/null | tail -c 200)
if echo "$SM" | grep -q "sourceMappingURL"; then
  emit "{\"title\":\"Source maps enabled in Next.js production build\",\"severity\":\"low\",\"description\":\"JavaScript bundles include source maps — original source code recoverable.\",\"remediation\":\"Set productionBrowserSourceMaps: false in next.config.js.\",\"cweId\":\"CWE-540\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
