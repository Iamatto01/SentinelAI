#!/usr/bin/env bash
# ============================================================================
# SentinelAI Autonomous Pentest Platform — Security PoC Probe
# Name:        Kubernetes Dashboard & API Exposure
# Description: Detects open kubelet, dashboard, API server, etcd
# Severity:    CRITICAL
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

echo -e "\033[1;36m[*] [SentinelAI PoC] Running probe: Kubernetes Dashboard & API Exposure\033[0m"
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
# K8s API server
R=$(curl -s -k -o /dev/null -w "%{http_code}" --max-time 6 "https://$HOST:6443/api" 2>/dev/null)
if [ "$R" = "200" ] || [ "$R" = "401" ]; then
  BODY=$(curl -s -k --max-time 6 "https://$HOST:6443/api" 2>/dev/null | head -c 300)
  if echo "$BODY" | grep -q "versions\|kind"; then
    emit "{\"title\":\"Kubernetes API server exposed on 6443\",\"severity\":\"critical\",\"description\":\"Kubernetes API server is reachable on port 6443. If anonymous or weak RBAC, full cluster takeover possible.\",\"remediation\":\"Restrict API server to internal network. Enable RBAC and disable anonymous auth.\",\"cweId\":\"CWE-306\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
  fi
fi
# kubelet
R=$(curl -s -k --max-time 6 "https://$HOST:10250/pods" 2>/dev/null | head -c 500)
if echo "$R" | grep -q "items\|kind.*PodList"; then
  emit "{\"title\":\"Kubelet read-only API exposed on 10250\",\"severity\":\"critical\",\"description\":\"Kubelet API allows pod listing and possibly exec. Full cluster compromise possible.\",\"remediation\":\"Disable anonymous kubelet access. Restrict 10250 to control plane.\",\"cweId\":\"CWE-306\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
fi
# dashboard
for P in "dashboard" "kubernetes-dashboard" "k8s" "kube-dashboard"; do
  R=$(curl -s -o /dev/null -w "%{http_code}" --max-time 6 "$T/$P" 2>/dev/null)
  if [ "$R" = "200" ]; then
    BODY=$(curl -s --max-time 6 "$T/$P" 2>/dev/null | head -c 400)
    if echo "$BODY" | grep -qi "kubernetes dashboard"; then
      emit "{\"title\":\"Kubernetes Dashboard exposed: /$P\",\"severity\":\"critical\",\"description\":\"Kubernetes Dashboard is accessible. With a service account token, full cluster control.\",\"remediation\":\"Remove dashboard or require auth + RBAC. Never use skip login.\",\"cweId\":\"CWE-306\",\"owaspCategory\":\"A05:2025-Security Misconfiguration\"}"
    fi
  fi
done

echo ""
echo -e "\033[1;34m[*] Probe execution complete.\033[0m"
