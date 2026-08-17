/**
 * Mock cPanel/WHM server simulating CVE-2026-41940 vulnerable behavior.
 * Used to E2E-test the detection chain in cpanel-authbypass.js.
 *
 * Simulates:
 *  - /openid_connect/cpanelid → 307 to canonical host
 *  - /login/?login_only=1 → whostmgrsession cookie with ",obhex" tail
 *  - GET / with Basic auth containing \r\n + stripped cookie → 307 leaking /cpsess##########
 *  - /scripts2/listaccts → 401 "Token denied"
 *  - /cpsess##########/json-api/version → 200 {"version":"11.110.0.89"}
 */
import http from 'node:http'

const CANONICAL = 'whm.mock.target'
const LEAKED_TOKEN = '/cpsess5691070609'

const server = http.createServer((req, res) => {
  const host = req.headers.host || ''
  const canonicalOk = host.startsWith(CANONICAL)

  // Stage 0 — wrong Host → 307 to canonical
  if (req.url === '/openid_connect/cpanelid') {
    if (!canonicalOk) { res.writeHead(307, { Location: `https://${CANONICAL}:2087/openid_connect/cpanelid` }); return res.end() }
    res.writeHead(200); return res.end('ok')
  }

  // Stage 1 — login mints session cookie with obfuscation tail
  if (req.url === '/login/?login_only=1' && req.method === 'POST') {
    res.writeHead(200, {
      'Set-Cookie': `whostmgrsession=%3AvQ2WC5Bexp0oFSa7%2C0a1b2c3d4e5f; path=/; HttpOnly`,
    })
    return res.end('login failed')
  }

  const auth = req.headers.authorization || ''
  const cookie = req.headers.cookie || ''

  // Stage 2 — CRLF injection: Basic auth with \r\n + cookie WITHOUT ob tail → 307 + token leak
  if (req.url === '/' && auth.startsWith('Basic ')) {
    const b64 = auth.slice(6)
    const decoded = Buffer.from(b64, 'base64').toString('utf8')
    const hasCrlf = decoded.includes('\r\n') && decoded.includes('hasroot=1')
    const cookieStripped = cookie.includes('whostmgrsession=') && !cookie.includes('%2C') && !cookie.includes(',')
    if (hasCrlf && cookieStripped) {
      res.writeHead(307, { Location: `https://${CANONICAL}:2087${LEAKED_TOKEN}/` })
      return res.end()
    }
    res.writeHead(401); return res.end('WHM Login')
  }

  // Stage 3 — do_token_denied gadget
  if (req.url === '/scripts2/listaccts') {
    res.writeHead(401); return res.end('Token denied')
  }

  // Stage 4 — verify WHM root with leaked token
  if (req.url === `${LEAKED_TOKEN}/json-api/version`) {
    res.writeHead(200, { 'Content-Type': 'application/json' })
    return res.end(JSON.stringify({ version: '11.110.0.89' }))
  }

  res.writeHead(404); res.end('not found')
})

server.listen(20870, '127.0.0.1', async () => {
  const { detectCpanelAuthBypass } = await import('../src/exploits/cpanel-authbypass.js')
  const r = await detectCpanelAuthBypass('http://127.0.0.1:20870', { hostname: CANONICAL })
  console.log(JSON.stringify({
    vulnerable: r.vulnerable,
    stages: r.stages,
    loot: r.loot?.data,
  }, null, 2))
  const pass = r.vulnerable === true
    && r.stages.length === 5
    && r.stages.every(s => s.ok)
    && r.loot?.data?.cpsessToken === LEAKED_TOKEN
    && r.loot?.data?.whmVersion === '11.110.0.89'
  console.log(pass ? '\n✅ E2E PASS — full detection chain verified' : '\n❌ E2E FAIL')
  // teardown: kill keep-alive sockets first, then hard exit (libuv assertion workaround)
  server.close()
  server.closeAllConnections?.()
  setTimeout(() => process.exit(pass ? 0 : 1), 200)
})
