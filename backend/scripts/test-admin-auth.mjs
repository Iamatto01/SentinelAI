async function test() {
  for (const ident of ['admin@sentinelai.com', 'admin']) {
    const res = await fetch('http://localhost:5000/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: ident, password: 'kali' })
    })
    const data = await res.json()
    console.log(`Login test for [${ident}]: HTTP ${res.status} | Role: ${data.user?.role} | Email: ${data.user?.email} | Token: ${Boolean(data.token)}`)

    if (data.token) {
      // Test fetching dashboard as admin
      const dash = await fetch('http://localhost:5000/api/dashboard', {
        headers: { Authorization: `Bearer ${data.token}` }
      })
      const dashData = await dash.json()
      console.log(`Dashboard access: HTTP ${dash.status} | Total Scans: ${dashData.totals?.scans} | Total Findings: ${dashData.totals?.findings}`)
    }
  }

  // Also test public domain
  const pubRes = await fetch('https://sentinelai.studio/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'admin@sentinelai.com', password: 'kali' })
  })
  const pubData = await pubRes.json()
  console.log(`Public domain [https://sentinelai.studio] login: HTTP ${pubRes.status} | Role: ${pubData.user?.role} | Token: ${Boolean(pubData.token)}`)
}

test()
