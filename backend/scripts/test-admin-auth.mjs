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

      // Test clients list (must be 0)
      const clients = await fetch('http://localhost:5000/api/admin/clients', {
        headers: { Authorization: `Bearer ${data.token}` }
      })
      const clientsData = await clients.json()
      console.log(`Admin Clients list: HTTP ${clients.status} | Total Clients: ${clientsData.totalClients} (Array: ${clientsData.clients?.length})`)

      // Test scans list
      const scans = await fetch('http://localhost:5000/api/scans', {
        headers: { Authorization: `Bearer ${data.token}` }
      })
      const scansData = await scans.json()
      console.log(`Scans access: HTTP ${scans.status} | Visible Scans: ${scansData.length}`)
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
