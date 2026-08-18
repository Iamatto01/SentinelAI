// E2E test: AI chatbox — NL → suggested command → execute → real output
const BASE = 'http://localhost:5000'

const login = await fetch(`${BASE}/api/auth/login`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: 'admin', password: 'kali' }),
}).then((r) => r.json())
const token = login.token
if (!token) {
  console.error('LOGIN FAILED:', login)
  process.exit(1)
}
const H = { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }

// 1. Ask AI for a command
console.log('\n=== 1. POST /api/kali/suggest — "check latest storage usage" ===')
const sugRes = await fetch(`${BASE}/api/kali/suggest`, {
  method: 'POST',
  headers: H,
  body: JSON.stringify({ message: 'check latest storage usage' }),
})
const suggestion = await sugRes.json()
console.log('status:', sugRes.status)
console.log('suggestion:', JSON.stringify(suggestion, null, 2))

if (!suggestion.command) {
  console.error('NO COMMAND SUGGESTED — FAIL')
  process.exit(1)
}

// 2. Execute the suggested command
console.log('\n=== 2. POST /api/kali/exec — running suggested command ===')
const execRes = await fetch(`${BASE}/api/kali/exec`, {
  method: 'POST',
  headers: H,
  body: JSON.stringify({ command: suggestion.command, timeout: 20000 }),
})
const execOut = await execRes.json()
console.log('status:', execRes.status)
console.log('exit code:', execOut.code)
console.log('stdout (first 600 chars):\n' + String(execOut.stdout || '').slice(0, 600))
if (execOut.stderr) console.log('stderr (first 200):', String(execOut.stderr).slice(0, 200))

// 3. Second ask with history context
console.log('\n=== 3. suggest with history — "what about memory?" ===')
const sug2 = await fetch(`${BASE}/api/kali/suggest`, {
  method: 'POST',
  headers: H,
  body: JSON.stringify({
    message: 'what about memory?',
    history: [
      { role: 'user', content: 'check latest storage usage' },
      { role: 'assistant', content: suggestion.explanation || 'df -h' },
    ],
  }),
})
const sug2j = await sug2.json()
console.log('status:', sug2.status)
console.log('suggestion:', JSON.stringify(sug2j, null, 2))

console.log('\n=== E2E COMPLETE ===')
