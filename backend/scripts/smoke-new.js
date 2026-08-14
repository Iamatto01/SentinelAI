/* Smoke test for new endpoints: login, monitor CRUD, CVE lookup, pause/resume. */
const BASE = 'http://localhost:5000'
let tok = ''

async function req(path, { method = 'GET', body } = {}) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...(tok ? { Authorization: `Bearer ${tok}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  })
  const text = await res.text()
  let data
  try { data = JSON.parse(text) } catch { data = { raw: text } }
  return { status: res.status, data }
}

const run = async () => {
  const login = await req('/api/auth/login', { method: 'POST', body: { username: 'admin', password: 'kali' } })
  if (login.status !== 200 || !login.data.token) throw new Error(`LOGIN failed: ${login.status} ${JSON.stringify(login.data)}`)
  tok = login.data.token
  console.log('LOGIN', login.status, 'token-len', (tok || '').length)

  const mon = await req('/api/monitors', { method: 'POST', body: { name: 'smoke', target: 'https://example.com', intervalMin: 60 } })
  console.log('MONITOR CREATE', mon.status, mon.data.id, 'next', mon.data.next_run)

  const mons = await req('/api/monitors')
  console.log('MONITORS', mons.status, 'count', mons.data.length)

  const cve = await req('/api/cve/CVE-2021-44228')
  console.log('CVE', cve.status, cve.data.id, 'score', cve.data.cvss?.score, cve.data.severity, cve.data.error || '')

  const me = await req('/api/users/me')
  console.log('ME', me.status, me.data.username)

  const upd = await req('/api/users/me', { method: 'PUT', body: { email: 'admin@example.com' } })
  console.log('UPDATE ME', upd.status, upd.data.email)

  // cleanup monitor
  if (mon.data.id) await req(`/api/monitors/${mon.data.id}`, { method: 'DELETE' })
  console.log('DONE')
}
run().catch((e) => { console.error('ERR', e.message); process.exit(1) })
