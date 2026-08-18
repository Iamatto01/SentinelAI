// Sanity check: authenticated engine status shape + tool counts
const BASE = 'http://localhost:5000'
const login = await fetch(`${BASE}/api/auth/login`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: 'admin', password: 'kali' }),
}).then(r => r.json())

const e = await fetch(`${BASE}/api/engine/status`, {
  headers: { Authorization: `Bearer ${login.token}` },
}).then(r => r.json())

console.log('keys:', Object.keys(e).join(', '))
for (const [k, v] of Object.entries(e)) {
  if (typeof v === 'number') console.log(` ${k} = ${v}`)
  else if (Array.isArray(v)) console.log(` ${k} = ${v.length} items`)
  else if (v && typeof v === 'object') console.log(` ${k} =`, JSON.stringify(v).slice(0, 200))
  else console.log(` ${k} =`, String(v).slice(0, 100))
}
