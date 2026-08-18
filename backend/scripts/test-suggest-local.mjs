// Quick local test of /api/kali/suggest
const BASE = 'http://localhost:5000'
const login = await fetch(`${BASE}/api/auth/login`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: 'admin', password: 'KaliTest2026!' }),
}).then((r) => r.json())
if (!login.token) {
  console.error('LOGIN FAILED:', login)
  process.exit(1)
}
const res = await fetch(`${BASE}/api/kali/suggest`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${login.token}` },
  body: JSON.stringify({ message: 'are all security tools up to date?' }),
})
console.log('status:', res.status)
console.log(JSON.stringify(await res.json(), null, 2))
