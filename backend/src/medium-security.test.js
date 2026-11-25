import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import fs from 'node:fs'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-medium-sec-'))
process.env.JWT_SECRET ||= 'test-only-jwt-secret-medium-sec'
process.env.DB_PATH = path.join(tmpDir, 'medium-sec.db')
process.env.OUTPUT_DIR = tmpDir

const { config } = await import('./config.js')
const db = await import('./db.js')
const { generateWafRules, modsecRuleId } = await import('./virtual-patching.js')
const kaliControl = await import('./kali-control.js')
const { llm } = await import('./ai/llm-client.js')
const { setupHoneypot, isIpTrapped, getClientIp, resetTrappedIps } = await import('./honeypot.js')
const { default: express } = await import('express')

let passed = 0
let failed = 0

async function test(name, fn) {
  try {
    await fn()
    passed++
    console.log(`  PASS: ${name}`)
  } catch (err) {
    failed++
    console.error(`  FAIL: ${name} -> ${err.stack || err.message}`)
  }
}

function createMockSpawn() {
  const calls = []
  const impl = (bin, args = [], opts = {}) => {
    const proc = new EventEmitter()
    let stdinWritten = ''
    proc.pid = 42424
    proc.stdout = new EventEmitter()
    proc.stderr = new EventEmitter()
    proc.stdin = new EventEmitter()
    proc.stdin.write = (chunk) => { stdinWritten += String(chunk) }
    proc.stdin.end = () => {}
    proc.kill = () => {}

    const record = { bin, args: [...args], opts: { ...opts }, get stdin() { return stdinWritten } }
    calls.push(record)

    queueMicrotask(() => {
      if (bin === 'top') {
        const lines = Array.from({ length: 60 }, (_, idx) => `line-${idx + 1}`).join('\n')
        proc.stdout.emit('data', Buffer.from(lines))
      } else {
        proc.stdout.emit('data', Buffer.from(`mock:${bin}`))
      }
      proc.emit('close', 0)
    })
    return proc
  }
  return { impl, calls }
}

async function httpRequest(port, method, reqPath, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path: reqPath, headers }, (res) => {
      let body = ''
      res.on('data', (d) => { body += d.toString() })
      res.on('end', () => {
        let json = null
        try { json = JSON.parse(body) } catch { /* non-json */ }
        resolve({ status: res.statusCode, headers: res.headers, body, json })
      })
    })
    req.on('error', reject)
    req.end()
  })
}

console.log('\n--- Running Medium Security (#8, #9, #13) Tests ---')

try {
  // ── Finding #8: virtual-patching.js ─────────────────────────────────────────
  await test('Medium #8: ModSecurity rule IDs are deterministic and bounded in [100000, 999999999]', () => {
    const findings = [
      { id: 'f-1', title: 'SQL injection in /api/search', module: 'sqli', evidence: { path: '/api/search' } },
      { id: 'f-2', title: 'Command injection in /api/run', module: 'cmdi', evidence: { path: '/api/run' } },
      { id: 'f-3', title: 'SSRF in /api/fetch', module: 'ssrf', evidence: { path: '/api/fetch' } },
      { id: 'f-4', title: 'Generic fallback issue', module: 'misc', evidence: {} },
      { id: 'f-5', title: 'Negative hash edge-case \uFFFF\uFFFF\uFFFF', module: 'xss', evidence: { path: '/x' } },
      {},
    ]

    for (const f of findings) {
      const r1 = generateWafRules(f)
      const r2 = generateWafRules(f)
      const m1 = r1.modSecurity.match(/\bid:(\d+)\b/)
      const m2 = r2.modSecurity.match(/\bid:(\d+)\b/)
      assert.ok(m1, `Expected numeric ModSec id in: ${r1.modSecurity}`)
      assert.equal(m1[1], m2[1], 'ModSecurity ID must be deterministic')
      const idNum = Number(m1[1])
      assert.ok(Number.isSafeInteger(idNum) && idNum >= 100000 && idNum <= 999999999, `ModSec ID ${idNum} out of range`)
      assert.ok(idNum <= 2147483647, `ModSec ID ${idNum} exceeds signed 32-bit int`)
    }

    assert.equal(modsecRuleId('edge-case'), modsecRuleId('edge-case'))
  })

  await test('Medium #8: Never generates unconditional root / or URI-only blocking rules across all families and WAFs', () => {
    const cases = [
      { title: 'OS Command Injection', module: 'cmd', evidence: {} },
      { title: 'OS Command Injection', module: 'cmd', evidence: { path: '/api/exec' } },
      { title: 'Server-Side Request Forgery (SSRF)', module: 'ssrf', evidence: { url: 'https://target.example/' } },
      { title: 'Server-Side Request Forgery (SSRF)', module: 'ssrf', evidence: { path: '/api/proxy' } },
      { title: 'Generic Misconfiguration', module: 'audit', evidence: {} },
      { title: 'Generic Misconfiguration', module: 'audit', evidence: { path: '/api/data' } },
      { title: 'SQL injection', module: 'sqli', evidence: {} },
      { title: 'Path traversal', module: 'lfi', evidence: {} },
      { title: 'Cross-Site Scripting (XSS)', module: 'xss', evidence: {} },
    ]

    for (const c of cases) {
      const r = generateWafRules(c)

      // Cloudflare: must include payload/query/body/header matches condition
      assert.match(r.cloudflare.expression, /\band\b/i, `Cloudflare rule must require inspection (${c.title}): ${r.cloudflare.expression}`)
      assert.match(r.cloudflare.expression, /\bmatches\b/i, `Cloudflare rule must inspect payload/header (${c.title}): ${r.cloudflare.expression}`)
      assert.equal(/^http\.request\.uri\.path\s+(eq|starts_with)\s+"\/"\s*$/.test(r.cloudflare.expression), false)

      // ModSecurity: must chain to secondary inspection SecRule with @rx
      assert.match(r.modSecurity, /SecRule REQUEST_URI/)
      assert.match(r.modSecurity, /\bchain\b/, `ModSecurity rule must chain payload inspection (${c.title}): ${r.modSecurity}`)
      assert.match(r.modSecurity, /SecRule\s+(?:REQUEST_URI\|)?ARGS.*@rx\s+/, `ModSecurity secondary rule must inspect payload (${c.title})`)

      // Nginx: must NEVER emit unconditional `location ~* ^\/$ { return 403; }` or bare return 403
      assert.equal(/location\s+~\*\s+\^\\?\/\$\s*\{\s*return\s+403;?\s*\}/.test(r.nginx), false, `Unconditional root nginx block emitted: ${r.nginx}`)
      assert.match(r.nginx, /if\s*\(\$(?:args|request_uri|http_[a-z_]+)\s+~\*\s+"/, `Nginx rule must guard 403 with payload/header regex (${c.title}): ${r.nginx}`)

      // AWS WAF: must NEVER be uriPath-only; must use andStatement combining uriPath and queryString/body/header inspection
      assert.equal(r.awsWaf.action, 'BLOCK')
      assert.ok(r.awsWaf.statement.andStatement, `AWS WAF must use andStatement (${c.title})`)
      const statements = r.awsWaf.statement.andStatement.statements
      assert.equal(statements.length, 2)
      assert.ok(statements[0].byteMatchStatement?.fieldToMatch?.uriPath)
      assert.ok(statements[1].orStatement?.statements?.length >= 2)
      assert.ok(
        statements[1].orStatement.statements.some((s) => s.regexMatchStatement?.fieldToMatch?.queryString || s.regexMatchStatement?.fieldToMatch?.body || s.regexMatchStatement?.fieldToMatch?.singleHeader),
        `AWS WAF must inspect queryString/body/headers (${c.title})`
      )
    }
  })

  // ── Finding #9: kali-control.js ─────────────────────────────────────────────
  await test('Medium #9: Rejects shell metacharacters, path traversal bins, and dangerous interpreter eval flags', async () => {
    const blocked = [
      'nmap 127.0.0.1; id',
      'ls && whoami',
      'ping -c 1 127.0.0.1 &',
      'cat /etc/passwd | grep root',
      'ls || id',
      'echo `whoami`',
      'echo $(id)',
      'echo ${PATH}',
      'echo pwn > /tmp/out',
      'cat < /etc/passwd',
      'ls\nid',
      'ls\rid',
      'echo "unclosed quote',
      '/tmp/evil/nmap 127.0.0.1',
      '../../bin/nmap 127.0.0.1',
      'python3 -c "import os"',
      'python3 -uc "print(1)"',
      'python --command="print(1)"',
      'python3 -i',
      'node -e "process.exit(1)"',
      'node --eval="console.log(1)"',
      'node -p "1+1"',
      'node -r fs',
      'node --import ./evil.mjs',
      'ruby -e "puts 1"',
      'perl -e "print 1"',
      'find /var -exec id +',
      'git -c core.fsmonitor=id status',
      'tar --to-command=id -xf a.tar',
      'env /bin/sh',
      'apt update',
      'apt-get install -y nmap',
      'dpkg -l',
      'nano /etc/hosts',
    ]

    for (const cmd of blocked) {
      await assert.rejects(() => kaliControl.executeCommand(cmd), (err) => {
        assert.ok(err instanceof Error && err.message.length > 0)
        return true
      }, `Expected command to be rejected: ${cmd}`)
    }
  })

  await test('Medium #9: Tokenizes safely into [bin, args], executes with shell:false, and handles htop/top cleanly', async () => {
    const mock = createMockSpawn()
    kaliControl.__setSpawnForTest(mock.impl)
    try {
      const res1 = await kaliControl.executeCommand('nmap -sV --script "http-title,http-headers" 127.0.0.1')
      assert.equal(res1.success, true)
      assert.equal(mock.calls.length, 1)
      assert.equal(mock.calls[0].bin, 'nmap')
      assert.deepEqual(mock.calls[0].args, ['-sV', '--script', 'http-title,http-headers', '127.0.0.1'])
      assert.equal(mock.calls[0].opts.shell, false)

      // Legitimate diagnostic interpreter version check still works
      const resPy = await kaliControl.executeCommand('python3 --version')
      assert.equal(resPy.success, true)
      assert.equal(mock.calls[1].bin, 'python3')
      assert.deepEqual(mock.calls[1].args, ['--version'])
      assert.equal(mock.calls[1].opts.shell, false)

      // htop translates safely to `top -b -n 1` with shell:false and 35-line cap
      const resHtop = await kaliControl.executeCommand('htop')
      assert.equal(resHtop.success, true)
      assert.equal(mock.calls[2].bin, 'top')
      assert.deepEqual(mock.calls[2].args, ['-b', '-n', '1'])
      assert.equal(mock.calls[2].opts.shell, false)
      assert.equal(resHtop.stdout.split('\n').length, 35)
    } finally {
      kaliControl.__setSpawnForTest(null)
    }
  })

  await test('Medium #9: manageService & runToolsInstallSteps pass sudo password via stdin with shell:false (never interpolated)', async () => {
    const prevPwd = config.kaliSudoPassword
    const adversarialPwd = 'p@ss; $(whoami) "quoted" & pipe|'
    config.kaliSudoPassword = adversarialPwd
    const mock = createMockSpawn()
    kaliControl.__setSpawnForTest(mock.impl)
    try {
      const svcRes = await kaliControl.manageService('sentinelai', 'restart')
      assert.equal(svcRes.success, true)
      assert.equal(mock.calls.length, 1)
      assert.equal(mock.calls[0].bin, 'sudo')
      assert.deepEqual(mock.calls[0].args, ['-S', '-p', '', 'systemctl', 'restart', 'sentinelai'])
      assert.equal(mock.calls[0].opts.shell, false)
      assert.equal(mock.calls[0].stdin, `${adversarialPwd}\n`)
      assert.equal(mock.calls[0].args.some((a) => a.includes(adversarialPwd)), false)

      // msfrpcd status runs systemctl + ss with shell:false
      await kaliControl.manageService('msfrpcd', 'status')
      assert.equal(mock.calls[1].bin, 'systemctl')
      assert.deepEqual(mock.calls[1].args, ['is-active', 'sentinelai'])
      assert.equal(mock.calls[1].opts.shell, false)
      assert.equal(mock.calls[2].bin, 'ss')
      assert.deepEqual(mock.calls[2].args, ['-lntp'])
      assert.equal(mock.calls[2].opts.shell, false)

      // Tools install runs array commands with shell:false and stdin sudo password
      mock.calls.length = 0
      await kaliControl.runToolsInstallSteps()
      assert.ok(mock.calls.length >= 5)
      for (const call of mock.calls) {
        assert.equal(call.opts.shell, false)
        assert.equal(call.args.some((a) => a.includes(adversarialPwd)), false)
        if (call.bin === 'sudo') {
          assert.equal(call.args[0], '-S')
          assert.equal(call.args[1], '-p')
          assert.equal(call.args[2], '')
          assert.equal(call.stdin, `${adversarialPwd}\n`)
        }
      }
    } finally {
      config.kaliSudoPassword = prevPwd
      kaliControl.__setSpawnForTest(null)
    }
  })

  await test('Medium #9: suggestKaliCommand aligns with ALLOWED_COMMANDS and rejects blocked/piped suggestions', async () => {
    assert.equal(kaliControl.ALLOWED_COMMANDS.includes('apt'), false)
    assert.equal(kaliControl.ALLOWED_COMMANDS.includes('apt-get'), false)
    assert.equal(kaliControl.ALLOWED_COMMANDS.includes('dpkg'), false)
    assert.equal(kaliControl.ALLOWED_COMMANDS.includes('whoami'), true)

    const origConfigured = llm.isConfigured.bind(llm)
    const origAnalyze = llm.analyze.bind(llm)
    let lastPrompt = ''
    llm.isConfigured = () => true

    try {
      llm.analyze = async (prompt) => {
        lastPrompt = prompt
        return JSON.stringify({ command: 'apt-get update', explanation: 'updates', risk: 'medium' })
      }
      await assert.rejects(() => kaliControl.suggestKaliCommand('update packages'), /not permitted/i)
      assert.equal(/\bapt-get\b/.test(lastPrompt.split('NO package managers')[0]), false)

      llm.analyze = async () => JSON.stringify({ command: 'ps aux | head -n 10', explanation: 'top procs', risk: 'low' })
      await assert.rejects(() => kaliControl.suggestKaliCommand('show processes'), /not permitted/i)

      llm.analyze = async () => JSON.stringify({ command: 'python3 -c "import os"', explanation: 'eval', risk: 'high' })
      await assert.rejects(() => kaliControl.suggestKaliCommand('run python'), /not permitted/i)

      // Free-text fallback must skip apt/dpkg and pick the first valid allowlisted command
      llm.analyze = async () => 'apt update\nfree -h'
      const fallbackRes = await kaliControl.suggestKaliCommand('check memory')
      assert.equal(fallbackRes.command, 'free -h')

      llm.analyze = async () => JSON.stringify({ command: 'df -h', explanation: 'Check disk usage', risk: 'low' })
      const okRes = await kaliControl.suggestKaliCommand('check disk')
      assert.equal(okRes.command, 'df -h')
      assert.doesNotThrow(() => kaliControl.parseAndValidateCommand(okRes.command))
    } finally {
      llm.isConfigured = origConfigured
      llm.analyze = origAnalyze
    }
  })

  // ── Finding #13: honeypot.js ────────────────────────────────────────────────
  await test('Medium #13: honeypot.js uses Express req.ip and ignores spoofed X-Forwarded-For headers', async () => {
    assert.equal(
      getClientIp({ ip: '192.168.1.55', headers: { 'x-forwarded-for': '8.8.8.8, 1.1.1.1' }, socket: { remoteAddress: '10.0.0.1' } }),
      '192.168.1.55'
    )

    // Case A: Direct LAN client (trust proxy = false) sending forged X-Forwarded-For headers
    resetTrappedIps()
    const directApp = express()
    directApp.set('trust proxy', false)
    setupHoneypot(directApp)
    directApp.get('/api/ping', (req, res) => res.json({ ok: true, ip: req.ip }))

    const directServer = http.createServer(directApp)
    await new Promise((resolve) => directServer.listen(0, '127.0.0.1', resolve))
    try {
      const { port } = directServer.address()
      for (const spoofed of ['1.1.1.1', '2.2.2.2', '3.3.3.3']) {
        const res = await httpRequest(port, 'GET', '/api/v1/system/master-dump', { 'X-Forwarded-For': spoofed })
        assert.equal(res.status, 403)
        assert.equal(isIpTrapped(spoofed), false, `Spoofed XFF ${spoofed} must NOT be tracked`)
      }

      // 4th request with yet another spoofed XFF must still be blocked 429 by real req.ip
      const blocked = await httpRequest(port, 'GET', '/api/ping', { 'X-Forwarded-For': '4.4.4.4' })
      assert.equal(blocked.status, 429)
      assert.equal(isIpTrapped('4.4.4.4'), false)
    } finally {
      await new Promise((resolve) => directServer.close(resolve))
    }

    // Case B: Behind 1 trusted proxy (trust proxy = 1), leftmost spoofed XFF entries are ignored
    resetTrappedIps()
    const proxyApp = express()
    proxyApp.set('trust proxy', 1)
    setupHoneypot(proxyApp)
    proxyApp.get('/api/ping', (req, res) => res.json({ ok: true, ip: req.ip }))

    const proxyServer = http.createServer(proxyApp)
    await new Promise((resolve) => proxyServer.listen(0, '127.0.0.1', resolve))
    try {
      const { port } = proxyServer.address()
      for (const spoofedLeft of ['9.9.9.9', '8.8.8.8', '7.7.7.7']) {
        const res = await httpRequest(port, 'GET', '/api/admin/backdoor-eval', {
          'X-Forwarded-For': `${spoofedLeft}, 203.0.113.77`,
        })
        assert.equal(res.status, 403)
        assert.equal(isIpTrapped(spoofedLeft), false)
      }
      assert.equal(isIpTrapped('203.0.113.77'), true)

      const blocked = await httpRequest(port, 'GET', '/api/ping', {
        'X-Forwarded-For': '6.6.6.6, 203.0.113.77',
      })
      assert.equal(blocked.status, 429)
    } finally {
      await new Promise((resolve) => proxyServer.close(resolve))
    }
  })

  console.log(`\nMedium Security Tests Complete: ${passed} passed, ${failed} failed.\n`)
  if (failed > 0) process.exit(1)
} finally {
  resetTrappedIps()
  try { db.getDb().close() } catch { /* ignore */ }
  fs.rmSync(tmpDir, { recursive: true, force: true })
}
