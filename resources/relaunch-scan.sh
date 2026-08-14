#!/bin/bash
# Login — uses admin password from .env or defaults to 'admin'
ADMIN_PASS="${DEFAULT_ADMIN_PASSWORD:-admin}"
TOKEN=$(curl -s -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PASS\"}" \
  | node -e "process.stdin.on('data',d=>{try{console.log(JSON.parse(d).token)}catch(e){console.error(d.toString());process.exit(1)}})")

# Stop the hung scan
echo "=== Stopping hung scan ==="
curl -s -X POST http://localhost:5000/api/scans/scan_93cd8ce7-422d-4298-b9fa-428c03dc7ddb/stop \
  -H "Authorization: Bearer $TOKEN"

# Launch a new scan against example.com
echo ""
echo "=== Launching new scan against example.com ==="
RESP=$(curl -s -X POST http://localhost:5000/api/scans \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"target":"http://example.com","mode":"blackbox","targetType":"url","template":"standard","modules":["nmap","whatweb","nikto","nuclei"],"objective":"comprehensive","maxTools":4,"verify":true,"depth":"standard"}')
echo "$RESP"
SCAN_ID=$(echo "$RESP" | node -e "process.stdin.on('data',d=>{try{console.log(JSON.parse(d).scan.id)}catch(e){console.error(d.toString());process.exit(1)}})")
echo "NEW_SCAN_ID: $SCAN_ID"
echo "$SCAN_ID" > /tmp/scan_id.txt