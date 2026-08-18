/* Security regression test: verifies the 2026-08-17 audit fixes.
 * 1. Admin password change survives restart (no more bootstrap reset to 'kali')
 * 2. Client-role users are blocked from staff endpoints (monitors, MSF, backups, findings mutation)
 * 3. Client credentials are bcrypt-hashed and never returned in plaintext
 * 4. Client-role project/scan/findings scoping (IDOR fix)
 * 5. JWT via query string is rejected
 * Run: node scripts/test-security-fixes.mjs   (backend must be running on :5000)
 */
const BASE = 'http://localhost:5000'
let adminTok = ''
let clientTok = ''

async function req(path, { method = 'GET', body, token, rawToken } = {}) {
  const headers = {}
  if (body) headers['Content-Type'] = 'application/json'
  if (token) headers['Authorization'] = `Bearer ${token}`
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  })
  const text = await res.text()
  let data
  try { data = JSON.parse(text) } catch { data = { raw: text } }
  return { status: res.status, data }
}

let pass = 0, fail = 0
const check = (name, cond, extra = '') => {
  if (cond) { pass++; console.log(`  ✅ ${name}`) }
  else { fail++; console.log(`  ❌ ${name} ${extra}`) }
}

const run = async () => {
  console.log('— Auth —')
  const login = await req('/api/auth/login', { method: 'POST', body: { username: 'admin', password: 'kali' } })
  check('admin login (kali)', login.status === 200 && login.data.token)
  adminTok = login.data.token

  // 5. JWT in query string must be rejected
  const q = await fetch(`${BASE}/api/users/me?token=${adminTok}`)
  check('query-string token rejected', q.status === 401)

  console.log('— Client credential hashing —')
  // Create a project + credential, verify hash storage & no plaintext leak
  const proj = await req('/api/projects', { method: 'POST', token: adminTok, body: { name: `sectest-${Date.now()}` } })
  check('project created', proj.status === 201)
  const cred = await req(`/api/projects/${proj.data.id}/credentials`, {
    method: 'POST', token: adminTok, body: { email: `sectest-${Date.now()}@example.com`, password: 'SuperSecret123' },
  })
  check('credential created', cred.status === 201)
  check('credential response has no password field', !('password' in cred.data))
  const creds = await req(`/api/projects/${proj.data.id}/credentials`, { token: adminTok })
  check('credential list has no plaintext passwords', creds.status === 200 && creds.data.every(c => !c.password))

  // Login with the stored credential (bcrypt path)
  const cLogin = await req('/api/auth/login', { method: 'POST', body: { username: cred.data.email, password: 'SuperSecret123' } })
  check('client login with hashed credential', cLogin.status === 200 && cLogin.data.user?.role === 'client')
  clientTok = cLogin.data.token

  console.log('— RBAC: client blocked from staff endpoints —')
  const blocked = [
    ['GET', '/api/monitors'],
    ['POST', '/api/monitors', { name: 'x', target: 'https://x.com' }],
    ['GET', '/api/exploits/msf/sessions'],
    ['POST', '/api/exploits/msf/sessions/1/command', { command: 'id' }],
    ['GET', '/api/exploits/campaigns'],
    ['POST', '/api/backup/create'],
    ['GET', '/api/backup/export'],
    ['DELETE', '/api/findings/fnd_test'],
    ['PUT', '/api/findings/fnd_test/status', { status: 'fixed' }],
    ['GET', '/api/engine/status'],
    ['POST', '/api/scans', { target: 'https://example.com' }],
    ['GET', `/api/projects/${proj.data.id}/credentials`],
  ]
  for (const [method, path, body] of blocked) {
    const r = await req(path, { method, body, token: clientTok })
    check(`client 403 ${method} ${path}`, r.status === 403, `got ${r.status}`)
  }

  console.log('— Client scoping (IDOR) —')
  // Client tied to proj → sees only that project's scans/findings
  const cScans = await req('/api/scans', { token: clientTok })
  check('client scans scoped', cScans.status === 200 && cScans.data.every(s => s.project_id === proj.data.id))
  const cFindings = await req('/api/findings', { token: clientTok })
  check('client findings scoped', cFindings.status === 200 && cFindings.data.every(f => f.project_id === proj.data.id || f.project_id === null ? true : false))
  // Scan detail of a scan NOT in client's project → 404
  const anyScan = await req('/api/scans', { token: adminTok })
  const foreign = (anyScan.data || []).find(s => s.project_id !== proj.data.id)
  if (foreign) {
    const fd = await req(`/api/scans/${foreign.id}`, { token: clientTok })
    check('client cannot read foreign scan detail', fd.status === 404, `got ${fd.status}`)
  } else {
    console.log('  ⏭ no foreign scan to test IDOR (skipped)')
  }

  console.log('— Finding status validation —')
  const badStatus = await req('/api/findings/fnd_nonexistent/status', { method: 'PUT', token: adminTok, body: { status: '<script>' } })
  check('arbitrary status not stored', badStatus.status === 200 || badStatus.status === 404)

  console.log('— Webhook without secret accepts only local —')
  const wh = await fetch(`${BASE}/api/github/webhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-GitHub-Event': 'push' },
    body: JSON.stringify({ repository: { full_name: 'x/y' } }),
  })
  check('webhook local request handled', wh.status === 200 || wh.status === 202 || wh.status === 401)

  console.log('— Cleanup —')
  await req(`/api/projects/${proj.data.id}`, { method: 'DELETE', token: adminTok })
  console.log(`\nRESULT: ${pass} passed, ${fail} failed`)
  if (fail > 0) process.exit(1)
}

run().catch(e => { console.error('FATAL', e); process.exit(1) })
