#!/bin/bash
set -e
TOKEN=$(curl -s -X POST http://localhost:5000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"kali"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')
echo "TOKEN_LEN=${#TOKEN}"
echo "--- RE-RUN SCAN ---"
curl -s -X POST 'http://localhost:5000/api/scans/scan_d8d71991-4f88-467e-8d21-5abd318aec87/re-run' \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json'
echo ""