#!/bin/bash
# Login
ADMIN_PASS="${DEFAULT_ADMIN_PASSWORD:-admin}"
LOGIN=$(curl -s -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PASS\"}")
echo "LOGIN: $LOGIN"
TOKEN=$(echo "$LOGIN" | node -e "process.stdin.on('data',d=>{try{console.log(JSON.parse(d).token)}catch(e){console.error(d.toString());process.exit(1)}})")
echo "TOKEN: ${TOKEN:0:30}..."

# Launch blackbox scan against a safe target (Acunetix test site)
RESP=$(curl -s -X POST http://localhost:5000/api/scans \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"target":"http://testphp.vulnweb.com","mode":"blackbox","targetType":"url","template":"standard","modules":["nmap","whatweb","nikto","nuclei"],"objective":"comprehensive","maxTools":4,"verify":true,"depth":"standard"}')
echo "SCAN RESPONSE: $RESP"
SCAN_ID=$(echo "$RESP" | node -e "process.stdin.on('data',d=>{try{console.log(JSON.parse(d).scan.id)}catch(e){console.error(d.toString());process.exit(1)}})")
echo "SCAN_ID: $SCAN_ID"
echo "$SCAN_ID" > /tmp/scan_id.txt
echo "Scan launched. ID saved to /tmp/scan_id.txt"