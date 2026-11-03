import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'

const scriptData = JSON.parse(
  await readFile(new URL('../src/data/default-custom-scripts.json', import.meta.url), 'utf8'),
)
const scripts = new Map(scriptData.map((script) => [script.name, script]))
const fallback = Buffer.from('<html><body>single page application fallback</body></html>')

const server = createServer((request, response) => {
  const pathname = new URL(request.url, 'http://localhost').pathname
  let status = 200
  let contentType = 'text/html'
  let body = fallback

  if (pathname === '/.hg/requires') {
    status = 403
    body = Buffer.from('Forbidden')
  } else if (pathname === '/.env') {
    contentType = 'text/plain'
    body = Buffer.from('APP_PASSWORD=supersecret_value_123\n')
  } else if (pathname === '/desktop.ini') {
    contentType = 'text/plain'
    body = Buffer.from('[.ShellClassInfo]\nIconResource=folder.ico\n')
  } else if (pathname === '/backup.zip') {
    contentType = 'application/zip'
    body = Buffer.from('PK\x03\x04archive-data', 'binary')
  } else if (pathname === '/api/v1/users/1') {
    contentType = 'application/json'
    body = Buffer.from('{"id":1,"email":"person@example.test"}')
  } else if (pathname === '/api' || pathname.startsWith('/api/')) {
    contentType = 'application/json'
    body = Buffer.from('{"items":[{"id":1}]}')
  }

  response.writeHead(status, {
    'Content-Type': contentType,
    'Content-Length': body.length,
  })
  if (request.method !== 'HEAD') response.end(body)
  else response.end()
})

function runScript(name, target) {
  const script = scripts.get(name)
  assert.ok(script, `Missing built-in script: ${name}`)

  return new Promise((resolve, reject) => {
    const child = spawn(process.env.BASH_PATH || 'bash', ['-c', script.command], {
      env: { ...process.env, TARGET: target },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    child.stdout.setEncoding('utf8').on('data', (chunk) => { stdout += chunk })
    child.stderr.setEncoding('utf8').on('data', (chunk) => { stderr += chunk })
    child.once('error', reject)
    child.once('close', (code) => {
      if (code !== 0) {
        reject(new Error(`${name} exited with ${code}: ${stderr}`))
        return
      }
      try {
        resolve(stdout.trim() ? stdout.trim().split('\n').map((line) => JSON.parse(line)) : [])
      } catch (error) {
        reject(new Error(`${name} emitted invalid JSONL: ${error.message}`))
      }
    })
  })
}

await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
const address = server.address()
const target = `http://127.0.0.1:${address.port}`

try {
  const config = await runScript('Environment & Config File Exposure (20 paths)', target)
  assert.equal(config.length, 1)
  assert.equal(config[0].severity, 'high')
  assert.equal(config[0].evidence.validationRequired, true)

  assert.deepEqual(await runScript('Admin Panel Discovery (30 paths)', target), [])
  assert.deepEqual(await runScript('Exposed .hg Repository (Mercurial)', target), [])

  const metadata = await runScript('OS Metadata File Exposure (.DS_Store, Thumbs.db, desktop.ini)', target)
  assert.equal(metadata.length, 1)
  assert.match(metadata[0].title, /signature confirmed/)

  const idor = await runScript('IDOR / BOLA Indicator Probe', target)
  assert.ok(idor.length > 0)
  assert.ok(idor.every((finding) => finding.severity === 'info' && finding.evidence.validationRequired))

  const backups = await runScript('Backup & Archive File Exposure (25 paths)', target)
  assert.equal(backups.length, 1)
  assert.equal(backups[0].severity, 'medium')
  assert.equal(backups[0].evidence.validationRequired, true)

  const rateLimits = await runScript('API Rate Limiting Test', target)
  assert.ok(rateLimits.length > 0)
  assert.ok(rateLimits.every((finding) => finding.severity === 'info' && finding.evidence.validationRequired))

  assert.deepEqual(await runScript('ASP.NET Security Checks', target), [])
  assert.deepEqual(await runScript('Next.js/Nuxt.js SPA Security Checks', target), [])
  assert.deepEqual(await runScript('Web Cache Deception Probe', target), [])

  console.log('Default script tuning tests passed.')
} finally {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))
}
