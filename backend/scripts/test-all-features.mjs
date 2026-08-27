/**
 * SentinelAI Comprehensive Feature & CRUD Test Suite
 * Tests Auth, Projects, Scans (including Delete), Findings, Monitors, Agents, Reports, and Billing
 */

const BASE_URL = process.env.BASE_URL || 'http://localhost:5000'

async function request(path, options = {}) {
  const url = `${BASE_URL}${path}`
  const res = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    }
  })
  const text = await res.text()
  let data
  try { data = JSON.parse(text) } catch { data = text }
  return { status: res.status, data, ok: res.ok }
}

async function runAllTests() {
  console.log(`\n======================================================`)
  console.log(`🛡️  SentinelAI Full Platform Feature Verification`)
  console.log(`🎯 Testing Target: ${BASE_URL}`)
  console.log(`======================================================\n`)

  let testsPassed = 0
  let testsFailed = 0

  function pass(name, detail = '') {
    testsPassed++
    console.log(`  ✅ [PASS] ${name} ${detail ? `(${detail})` : ''}`)
  }

  function fail(name, error) {
    testsFailed++
    console.error(`  ❌ [FAIL] ${name}:`, error)
  }

  try {
    // 1. Health & Public Info
    console.log(`\n[1/10] Testing Public Health & Info Endpoints...`)
    const health = await request('/api/health')
    if (health.ok && health.data.ok) pass('GET /api/health', `Agents: ${health.data.agentsCount}`)
    else fail('GET /api/health', JSON.stringify(health.data))

    const stats = await request('/api/public/stats')
    if (stats.ok && stats.data.agentsCount >= 50) pass('GET /api/public/stats', `${stats.data.agentsCount} agents, ${stats.data.toolsCount} tools`)
    else fail('GET /api/public/stats', JSON.stringify(stats.data))

    const publicAgents = await request('/api/public/agents')
    if (publicAgents.ok && Array.isArray(publicAgents.data)) pass('GET /api/public/agents', `${publicAgents.data.length} agents listed`)
    else fail('GET /api/public/agents', JSON.stringify(publicAgents.data))

    // 2. Authentication & User Lifecycle
    console.log(`\n[2/10] Testing Authentication & User Lifecycle...`)
    const timestamp = Date.now()
    const testUsername = `test_admin_${timestamp}`
    const testEmail = `test_admin_${timestamp}@sentinelai.studio`
    const testPassword = 'Password123!Secure'

    const reg = await request('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ username: testUsername, email: testEmail, password: testPassword })
    })
    if (reg.ok && reg.data.token) pass('POST /api/auth/register', `User ID: ${reg.data.user.id}`)
    else fail('POST /api/auth/register', JSON.stringify(reg.data))

    const token = reg.data.token
    const authHeaders = { Authorization: `Bearer ${token}` }

    const me = await request('/api/auth/me', { headers: authHeaders })
    if (me.ok && me.data.user.username === testUsername) pass('GET /api/auth/me', `Verified: ${me.data.user.username}`)
    else fail('GET /api/auth/me', JSON.stringify(me.data))

    // 3. Projects / Folders CRUD
    console.log(`\n[3/10] Testing Projects / Folders CRUD...`)
    const createProj = await request('/api/projects', {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        name: `Test Folder ${timestamp}`,
        client: 'Test Client Corp',
        description: 'Automated test folder for verifying deletion & management',
        scope: 'https://test-scope.local',
        riskLevel: 'high'
      })
    })
    let createdProjectId = null
    if (createProj.ok && createProj.data.id) {
      createdProjectId = createProj.data.id
      pass('POST /api/projects (Create Folder)', `ID: ${createdProjectId}`)
    } else {
      fail('POST /api/projects', JSON.stringify(createProj.data))
    }

    const listProjs = await request('/api/projects', { headers: authHeaders })
    if (listProjs.ok && Array.isArray(listProjs.data)) pass('GET /api/projects', `${listProjs.data.length} folders/projects returned`)
    else fail('GET /api/projects', JSON.stringify(listProjs.data))

    if (createdProjectId) {
      const updateProj = await request(`/api/projects/${createdProjectId}`, {
        method: 'PUT',
        headers: authHeaders,
        body: JSON.stringify({
          name: `Updated Test Folder ${timestamp}`,
          description: 'Updated description'
        })
      })
      if (updateProj.ok && updateProj.data.name.includes('Updated')) pass('PUT /api/projects/:id', 'Folder renamed')
      else fail('PUT /api/projects/:id', JSON.stringify(updateProj.data))
    }

    // 4. Scans CRUD & Pipeline Integration (including DELETE)
    console.log(`\n[4/10] Testing Scans CRUD & Delete Action...`)
    const createScan = await request('/api/scans', {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        target: 'https://demo-test.local',
        targetType: 'url',
        mode: 'blackbox',
        template: 'quick',
        projectId: createdProjectId,
        modules: ['web_app_scanner']
      })
    })
    let createdScanId = null
    if (createScan.ok && createScan.data.scan?.id) {
      createdScanId = createScan.data.scan.id
      pass('POST /api/scans (Launch Scan)', `Scan ID: ${createdScanId}`)
    } else {
      fail('POST /api/scans', JSON.stringify(createScan.data))
    }

    const listScans = await request('/api/scans', { headers: authHeaders })
    if (listScans.ok && Array.isArray(listScans.data)) pass('GET /api/scans', `${listScans.data.length} scans returned`)
    else fail('GET /api/scans', JSON.stringify(listScans.data))

    if (createdScanId) {
      const getScan = await request(`/api/scans/${createdScanId}`, { headers: authHeaders })
      if (getScan.ok && getScan.data.scan?.id === createdScanId) pass('GET /api/scans/:id', `Status: ${getScan.data.scan.status}`)
      else fail('GET /api/scans/:id', JSON.stringify(getScan.data))

      // Stop scan
      const stopScan = await request(`/api/scans/${createdScanId}/stop`, {
        method: 'POST',
        headers: authHeaders
      })
      if (stopScan.ok) pass('POST /api/scans/:id/stop', 'Scan aborted cleanly')
      else fail('POST /api/scans/:id/stop', JSON.stringify(stopScan.data))

      // Crucial test: DELETE SCAN (User's reported bug)
      const deleteScanRes = await request(`/api/scans/${createdScanId}`, {
        method: 'DELETE',
        headers: authHeaders
      })
      if (deleteScanRes.ok && deleteScanRes.data.ok) {
        pass('DELETE /api/scans/:id', `Scan ${createdScanId} deleted with transaction safety!`)
      } else {
        fail('DELETE /api/scans/:id', JSON.stringify(deleteScanRes.data))
      }

      // Verify it is gone
      const verifyGone = await request(`/api/scans/${createdScanId}`, { headers: authHeaders })
      if (verifyGone.status === 404) pass('Verify Scan Deletion', 'Confirmed 404 Not Found')
      else fail('Verify Scan Deletion', `Scan still returned status ${verifyGone.status}`)
    }

    // 5. Delete Folder / Project
    console.log(`\n[5/10] Testing Folder / Project Deletion...`)
    if (createdProjectId) {
      const deleteProjRes = await request(`/api/projects/${createdProjectId}`, {
        method: 'DELETE',
        headers: authHeaders
      })
      if (deleteProjRes.ok && deleteProjRes.data.ok) {
        pass('DELETE /api/projects/:id', `Folder ${createdProjectId} deleted cleanly!`)
      } else {
        fail('DELETE /api/projects/:id', JSON.stringify(deleteProjRes.data))
      }
    }

    // 6. Findings & Notes
    console.log(`\n[6/10] Testing Vulnerability Findings & Management...`)
    const findingsList = await request('/api/findings', { headers: authHeaders })
    if (findingsList.ok && Array.isArray(findingsList.data)) {
      pass('GET /api/findings', `${findingsList.data.length} findings available`)
      if (findingsList.data.length > 0) {
        const sampleFinding = findingsList.data[0]
        const updateStatus = await request(`/api/findings/${sampleFinding.id}/status`, {
          method: 'PUT',
          headers: authHeaders,
          body: JSON.stringify({ status: 'confirmed' })
        })
        if (updateStatus.ok) pass('PUT /api/findings/:id/status', `Status set to confirmed`)
        else fail('PUT /api/findings/:id/status', JSON.stringify(updateStatus.data))
      }
    } else {
      fail('GET /api/findings', JSON.stringify(findingsList.data))
    }

    // 7. Monitors Management
    console.log(`\n[7/10] Testing Attack Surface Continuous Monitors...`)
    const createMon = await request('/api/monitors', {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        name: `Automated Monitor ${timestamp}`,
        target: 'https://test-monitor.local',
        targetType: 'url',
        intervalMin: 120,
        modules: ['web_app_scanner']
      })
    })
    let monId = null
    if (createMon.ok && createMon.data.id) {
      monId = createMon.data.id
      pass('POST /api/monitors (Create Monitor)', `Monitor ID: ${monId}`)
    } else {
      fail('POST /api/monitors', JSON.stringify(createMon.data))
    }

    if (monId) {
      const delMon = await request(`/api/monitors/${monId}`, {
        method: 'DELETE',
        headers: authHeaders
      })
      if (delMon.ok) pass('DELETE /api/monitors/:id', `Monitor ${monId} deleted`)
      else fail('DELETE /api/monitors/:id', JSON.stringify(delMon.data))
    }

    // 8. AI Specialists & Copilot
    console.log(`\n[8/10] Testing AI Specialists & Copilot Chat...`)
    const agentList = await request('/api/agents', { headers: authHeaders })
    if (agentList.ok && Array.isArray(agentList.data) && agentList.data.length >= 50) {
      pass('GET /api/agents', `${agentList.data.length} Specialist Personas Loaded`)
    } else {
      fail('GET /api/agents', JSON.stringify(agentList.data))
    }

    const cveSearch = await request('/api/cve/search?product=apache&version=2.4.49', { headers: authHeaders })
    if (cveSearch.ok) pass('GET /api/cve/search', 'CVE intelligence query succeeded')
    else fail('GET /api/cve/search', JSON.stringify(cveSearch.data))

    // 9. Billing, Quota & Subscriptions
    console.log(`\n[9/10] Testing Billing, Subscriptions & Consultation...`)
    const sub = await request('/api/billing/subscription', { headers: authHeaders })
    if (sub.ok && sub.data.plan) pass('GET /api/billing/subscription', `Plan: ${sub.data.plan.name}`)
    else fail('GET /api/billing/subscription', JSON.stringify(sub.data))

    const upgrade = await request('/api/billing/upgrade', {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({ planId: 'pro', billingInterval: 'monthly' })
    })
    if (upgrade.ok && upgrade.data.ok) pass('POST /api/billing/upgrade', 'Instant Pro upgrade activated')
    else fail('POST /api/billing/upgrade', JSON.stringify(upgrade.data))

    const txHistory = await request('/api/billing/history', { headers: authHeaders })
    if (txHistory.ok && Array.isArray(txHistory.data)) pass('GET /api/billing/history', `${txHistory.data.length} transactions recorded`)
    else fail('GET /api/billing/history', JSON.stringify(txHistory.data))

    // 10. Dashboard & Analytics
    console.log(`\n[10/10] Testing Unified Dashboard & Database Backups...`)
    const dashboard = await request('/api/dashboard', { headers: authHeaders })
    if (dashboard.ok && dashboard.data.counts) pass('GET /api/dashboard', `Scans: ${dashboard.data.counts.totalScans}, Findings: ${dashboard.data.counts.totalFindings}`)
    else fail('GET /api/dashboard', JSON.stringify(dashboard.data))

    const backupExport = await request('/api/backup/export', { headers: authHeaders })
    if (backupExport.ok && backupExport.data.counts) pass('GET /api/backup/export', `Exported ${backupExport.data.counts.scans} scans, ${backupExport.data.counts.findings} findings`)
    else fail('GET /api/backup/export', JSON.stringify(backupExport.data))

  } catch (err) {
    console.error('Fatal test error:', err)
    testsFailed++
  }

  console.log(`\n======================================================`)
  console.log(`📊 FINAL TEST SUMMARY:`)
  console.log(`   Passed: ${testsPassed}`)
  console.log(`   Failed: ${testsFailed}`)
  console.log(`======================================================\n`)

  if (testsFailed > 0) {
    process.exit(1)
  }
}

runAllTests()
