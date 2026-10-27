#!/usr/bin/env bash
# ==============================================================================
# SentinelAI Master PoC Runner
# Execute vulnerability PoC probes against a specific target.
# ==============================================================================

TARGET="${1:-${TARGET:-}}"
CATEGORY="${2:-all}"

if [ -z "$TARGET" ]; then
  echo "[-] Usage:   $0 <target_url> [category]"
  echo "[-] Example: $0 https://example.com 01_information_disclosure"
  echo "[-] Example: $0 https://example.com all"
  echo ""
  echo "Available Categories:"
  echo "  1) 01_information_disclosure"
  echo "  2) 02_injection_flaws"
  echo "  3) 03_access_control_and_auth"
  echo "  4) 04_network_and_infra"
  echo "  5) 05_misconfigurations"
  echo "  6) 06_framework_and_api"
  echo "  7) all (runs every check in sequence)"
  exit 1
fi

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

run_category() {
  local cat_dir="$BASE_DIR/$1"
  if [ -d "$cat_dir" ]; then
    echo "=================================================================="
    echo ">>> Running Category: $1"
    echo "=================================================================="
    for s in "$cat_dir"/*.sh; do
      if [ -f "$s" ]; then
        bash "$s" "$TARGET"
        echo "------------------------------------------------------------------"
      fi
    done
  fi
}

if [ "$CATEGORY" == "all" ]; then
  for c in "01_information_disclosure" "02_injection_flaws" "03_access_control_and_auth" "04_network_and_infra" "05_misconfigurations" "06_framework_and_api"; do
    run_category "$c"
  done
else
  run_category "$CATEGORY"
fi
