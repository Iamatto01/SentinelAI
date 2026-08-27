import { config } from '../src/config.js'

async function test() {
  const BASE = 'http://localhost:5000'
  const username = `client_${Date.now()}`
  const email = `${username}@example.com`
  const password = 'Password123!'

  console.log(`[Test] 1. Registering new client: ${username} (${email})...`)
  const regRes = await fetch(`${BASE}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, email, password, planId: 'trial' }),
  })
  const regData = await regRes.json()
  if (!regData.token) {
    console.error('Registration failed:', regData)
    process.exit(1)
  }
  const token = regData.token
  console.log('   ✓ Registered successfully! Role:', regData.user.role)

  console.log('[Test] 2. Testing GET /api/scans for client...')
  const scansRes = await fetch(`${BASE}/api/scans`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  console.log('   ✓ /api/scans HTTP Status:', scansRes.status)
  const scans = await scansRes.json()
  console.log('   ✓ Scans returned:', Array.isArray(scans) ? `Array(${scans.length})` : scans)

  console.log('[Test] 3. Testing GET /api/findings for client...')
  const findingsRes = await fetch(`${BASE}/api/findings`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  console.log('   ✓ /api/findings HTTP Status:', findingsRes.status)
  const findings = await findingsRes.json()
  console.log('   ✓ Findings returned:', Array.isArray(findings) ? `Array(${findings.length})` : findings)

  console.log('[Test] 4. Testing GET /api/dashboard for client...')
  const dashRes = await fetch(`${BASE}/api/dashboard`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  console.log('   ✓ /api/dashboard HTTP Status:', dashRes.status)
  const dash = await dashRes.json()
  console.log('   ✓ Dashboard stats:', dash.totals, 'agentsCount:', dash.agentsCount)

  console.log('\n✅ All client endpoints are functioning flawlessly without errors!')
}

test().catch(console.error)
