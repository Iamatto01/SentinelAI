// Verify sentinelai.studio (public tunnel) end-to-end: login + kali suggest
const BASE = 'https://sentinelai.studio'
const login = await fetch(`${BASE}/api/auth/login`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: 'admin', password: 'kali' }),
}).then((r) => r.json())
if (!login.token) {
  console.error('LOGIN FAILED:', login)
  process.exit(1)
}
console.log('login: OK (role:', login.user.role + ')')
const res = await fetch(`${BASE}/api/kali/suggest`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${login.token}` },
  body: JSON.stringify({ message: 'check disk space' }),
})
console.log('kali/suggest status:', res.status)
console.log(JSON.stringify(await res.json(), null, 2))
