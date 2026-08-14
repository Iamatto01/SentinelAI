#!/bin/bash
SCAN_ID=$(cat /tmp/scan_id.txt)
ADMIN_PASS="${DEFAULT_ADMIN_PASSWORD:-admin}"
TOKEN=$(curl -s -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PASS\"}" | node -e "process.stdin.on('data',d=>{try{console.log(JSON.parse(d).token)}catch(e){console.error(d.toString());process.exit(1)}})")

RESP=$(curl -s http://localhost:5000/api/scans/$SCAN_ID \
  -H "Authorization: Bearer $TOKEN")

echo "$RESP" | node -e "
process.stdin.on('data',d=>{
  const j=JSON.parse(d);
  console.log('=== STATUS:', j.scan.status, '| Progress:', j.scan.progress + '%', '| Risk:', (j.scan.risk_score || 0).toFixed(1), '/10 | Findings:', j.findings.length);
  console.log('');
  console.log('--- Recent Logs ---');
  j.logs.slice(-20).forEach(l => console.log('[' + l.level + ']', l.message));
  console.log('');
  if (j.findings.length > 0) {
    console.log('--- Findings ---');
    j.findings.forEach(f => console.log('[' + f.severity + ']', f.title, '|', f.owasp_category || ''));
  }
  if (j.whiteboxMeta) {
    console.log('');
    console.log('--- Whitebox Meta ---');
    console.log('Files:', j.whiteboxMeta.totalFiles, 'Passes:', j.whiteboxMeta.passes?.length);
    j.whiteboxMeta.passes?.forEach(p => console.log(p.status, '|', p.tool, '|', p.type, '|', p.findings + ' findings', '|', (p.durationMs/1000).toFixed(1) + 's', p.error ? '| ERROR: ' + p.error : ''));
  }
})
"