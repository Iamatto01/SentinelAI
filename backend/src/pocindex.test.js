import assert from 'node:assert/strict'
import http from 'node:http'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import Database from 'better-sqlite3'

import { config } from './config.js'
import pocindex, {
  verifyPocindexDatabase,
  searchCves,
  getCveDetail,
  enrichCveWithPocindex,
  closePocindexDb,
  getPocindexStats,
} from './integrations/pocindex.js'
import pocindexSync, {
  streamJsonArray,
  streamJsonObjectEntries,
  syncNow,
  correlateAndAlertFindings,
} from './integrations/pocindex-sync.js'
import { buildVersionFinding } from './version-audit.js'
import { evaluateFindingCvss } from './cvss4.js'
import { buildCveIntelContext } from './ai/ai-engine.js'

function chunkedReadableStream(str, chunkSize = 7) {
  const bytes = new TextEncoder().encode(str)
  let offset = 0
  return new ReadableStream({
    pull(controller) {
      if (offset >= bytes.length) {
        controller.close()
        return
      }
      controller.enqueue(bytes.slice(offset, offset + chunkSize))
      offset += chunkSize
    },
  })
}

async function runTests() {
  let passed = 0
  const check = (name, cond, extra = '') => {
    assert.ok(cond, `${name}${extra ? ` (${extra})` : ''}`)
    passed++
    console.log(`  PASS: ${name}`)
  }

  console.log('\n[pocindex] 1. Streaming JSON parser edge cases')
  {
    const sampleArr = [
      { cve: 'CVE-2024-0001', desc: 'Escaped "quote" and braces {a:[1,2]} — UTF8 Ω', poc: ['https://github.com/a/b'] },
      { cve: 'CVE-2024-0002', desc: 'Normal item \\ backslash test', poc: [] },
    ]
    const parsedArr = []
    const countA = await streamJsonArray(
      chunkedReadableStream(JSON.stringify(sampleArr), 5),
      (batch) => parsedArr.push(...batch),
      { batchSize: 1 },
    )
    check('streamJsonArray count matches', countA === 2)
    check('streamJsonArray preserves escaped quotes & braces & unicode', parsedArr[0].desc === sampleArr[0].desc)
    check('streamJsonArray preserves backslash', parsedArr[1].desc === sampleArr[1].desc)

    const sampleObj = {
      'CVE-2024-0001': { cvss: [['3.1', 9.8, 'CRITICAL', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'nvd@nist.gov', 'Primary']], advisories: [['https://example.com/{id}', ['Patch']]] },
      'CVE-2024-0002': { cvss: [], advisories: [] },
    }
    const parsedEntries = []
    const countO = await streamJsonObjectEntries(
      chunkedReadableStream(JSON.stringify(sampleObj), 7),
      (batch) => parsedEntries.push(...batch),
      { batchSize: 1 },
    )
    check('streamJsonObjectEntries count matches', countO === 2)
    check('streamJsonObjectEntries key/value accurate', parsedEntries[0][0] === 'CVE-2024-0001' && parsedEntries[0][1].cvss[0][1] === 9.8)
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pocindex-test-'))
  const testDbPath = path.join(tmpDir, 'pocindex.db')
  const fakeFypPath = path.join(tmpDir, 'fyp2-test.db')
  const stubDbPath = path.join(tmpDir, 'stub.db')

  // Create AGENTS.md §3 stub database (valid sqlite file, 0 tables)
  {
    const stub = new Database(stubDbPath)
    stub.exec('CREATE TABLE t(x INT); DROP TABLE t;')
    stub.close()
    const checkStub = verifyPocindexDatabase(stubDbPath, { minCves: 0 })
    check('rejects 0-table stub SQLite database even when integrity=ok', checkStub.ok === false && checkStub.integrity === 'ok')
  }

  // Save original config values and point strictly to temp paths
  const prevPocConfig = { ...config.pocindex }
  config.pocindex.enabled = true
  config.pocindex.autoSync = false
  config.pocindex.dbPath = testDbPath

  let kevVersion = 1
  const mockFixtures = () => ({
    '/stats.json': { etag: '"stats-v1"', body: { total_cves: 176958, with_pocs: 3, kev: kevVersion === 1 ? 1 : 2 } },
    '/trending_poc.json': {
      etag: '"trend-v1"',
      body: {
        generated: '2026-11-25T00:00:00Z',
        items: [{ cve: 'CVE-2021-44228', name: 'log4j-rce', stars: 1500, kev: true, url: 'https://github.com/kozmer/log4j-shell-poc' }],
        landed: [{ cve: 'CVE-2024-9999', name: 'new-poc', stars: 42, kev: kevVersion > 1, url: 'https://github.com/org/new-poc', released: '2026-11-25T01:00:00Z' }],
      },
    },
    '/kev.json': {
      etag: `"kev-v${kevVersion}"`,
      body: kevVersion === 1
        ? { 'CVE-2021-44228': ['2021-12-10', '2021-12-24'] }
        : { 'CVE-2021-44228': ['2021-12-10', '2021-12-24'], 'CVE-2024-9999': ['2026-11-25', '2026-12-09'] },
    },
    '/epss.json': {
      etag: '"epss-v1"',
      body: {
        'CVE-2021-44228': [0.975, 0.9998],
        'CVE-2024-3094': [0.812, 0.991],
        'CVE-2024-9999': [0.45, 0.91],
      },
    },
    '/nuclei.json': {
      etag: '"nuclei-v1"',
      body: {
        'CVE-2021-44228': { severity: 'critical', cvss: 10.0, cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', cwe: 'CWE-502' },
      },
    },
    '/repo_meta.json': {
      etag: '"repo-v1"',
      body: {
        'Kozmer/log4j-shell-poc': [1500, '2026-01-01'],
        'other/apache-windows-poc': [12, '2025-05-05'],
      },
    },
    '/CVE_list.json': {
      etag: '"cvelist-v1"',
      body: [
        {
          cve: 'CVE-2021-44228',
          title: 'Apache Log4j2 JNDI RCE',
          desc: 'Apache Log4j2 remote code execution via JNDI LDAP lookup.',
          vendor: ['Apache'],
          product: ['Log4j'],
          published: '2021-12-10',
          modified: '2026-10-01',
          poc: ['https://github.com/kozmer/log4j-shell-poc'],
          nuclei: ['https://github.com/projectdiscovery/nuclei-templates/blob/main/CVE-2021-44228.yaml'],
          msf: ['https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/http/log4shell.rb'],
          edb: ['https://www.exploit-db.com/exploits/50592'],
          vulhub: ['https://github.com/vulhub/vulhub/tree/master/log4j/CVE-2021-44228'],
        },
        {
          cve: 'CVE-2024-3094',
          title: 'Apache Windows Legacy Issue',
          desc: 'Example Apache on Windows component issue for exclusion test.',
          vendor: ['Apache'],
          product: ['HTTP Server Windows'],
          published: '2024-03-29',
          modified: '2025-01-01',
          poc: ['https://github.com/other/apache-windows-poc'],
        },
        {
          cve: 'CVE-2024-9999',
          title: 'Nginx Request Smuggling Edge Bug',
          desc: 'Nginx proxy smuggling bug with public repo.',
          vendor: ['F5'],
          product: ['nginx'],
          published: '2024-09-01',
          modified: '2026-11-25',
          poc: ['https://github.com/org/new-poc'],
        },
      ],
    },
    '/cve_metadata.json': {
      etag: '"cvemeta-v1"',
      body: {
        'CVE-2021-44228': {
          cvss: [['3.1', 10.0, 'CRITICAL', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 'nvd@nist.gov', 'Primary']],
          advisories: [['https://logging.apache.org/log4j/2.x/security.html', ['Vendor Advisory']]],
        },
        'CVE-2024-3094': {
          cvss: [['3.1', 7.5, 'HIGH', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N', 'nvd@nist.gov', 'Primary']],
          advisories: [],
        },
        'CVE-2024-9999': {
          cvss: [['3.1', 8.2, 'HIGH', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N', 'nvd@nist.gov', 'Primary']],
          advisories: [],
        },
      },
    },
  })

  const server = http.createServer((req, res) => {
    const f = mockFixtures()[req.url]
    if (!f) {
      res.statusCode = 404
      res.end('not found')
      return
    }
    const inm = req.headers['if-none-match']
    if (inm && inm === f.etag) {
      res.statusCode = 304
      res.setHeader('ETag', f.etag)
      res.end()
      return
    }
    res.statusCode = 200
    res.setHeader('Content-Type', 'application/json')
    res.setHeader('ETag', f.etag)
    res.end(JSON.stringify(f.body))
  })

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = server.address().port
  config.pocindex.baseUrl = `http://127.0.0.1:${port}`

  try {
    console.log('\n[pocindex] 2. Full sync, ETag 304 caching & atomic staging swap')
    const res1 = await syncNow({ full: true })
    check('initial full sync succeeds', res1.ok === true && res1.mode === 'full-rebuild')
    check('initial sync indexes all 3 CVEs', res1.indexedCves === 3)
    check('staging verified & swapped to pocindex.db', verifyPocindexDatabase(testDbPath, { minCves: 3 }).ok)

    const res2 = await syncNow({ full: true })
    check('second sync hits 304 Not Modified cleanly', res2.ok === true && res2.updated === false)

    console.log('\n[pocindex] 3. Delta KEV update when CVE_list returns 304')
    kevVersion = 2
    const res3 = await syncNow({ full: true })
    check('delta sync runs without rebuilding CVE_list', res3.ok === true && res3.mode === 'delta')
    check('newly added KEV flag is reflected in CVE-2024-9999', Boolean(enrichCveWithPocindex('CVE-2024-9999')?.kev))

    console.log('\n[pocindex] 4. FTS5 search, negation, filters & sorting')
    const rExact = searchCves('CVE-2021-44228')
    check('exact CVE lookup finds Log4j', rExact.total === 1 && rExact.items[0].cveId === 'CVE-2021-44228')

    const rNeg = searchCves('apache -windows')
    check('FTS5 negation excludes -windows match', rNeg.total === 1 && rNeg.items[0].cveId === 'CVE-2021-44228')

    const rPureNeg = searchCves('-windows')
    check('pure negative query falls back cleanly without FTS syntax error', rPureNeg.total === 2 && !rPureNeg.items.some(i => i.cveId === 'CVE-2024-3094'))

    const rMsf = searchCves('', { source: 'msf', kev: true })
    check('filter source=msf & kev=true returns only Log4j', rMsf.total === 1 && rMsf.items[0].cveId === 'CVE-2021-44228')

    const rMinEpss = searchCves('', { minEpss: 0.9, sort: 'epss' })
    check('filter minEpss=0.9 narrows results accurately', rMinEpss.total === 1 && rMinEpss.items[0].epss.score === 0.975)

    const detail = getCveDetail('CVE-2021-44228')
    check('getCveDetail resolves case-insensitive repo_meta stars (1500)', detail?.topStars === 1500 && detail?.pocs?.github?.[0]?.stars === 1500)
    check('getCveDetail groups EDB, MSF, Nuclei & Vulhub sources', detail.pocs.edb.length === 1 && detail.pocs.msf.length === 1 && detail.pocs.vulhub.length === 1 && detail.pocs.nuclei.length === 1)

    const stats = await getPocindexStats()
    check('getPocindexStats aggregates DB + upstream counts', stats.available && stats.indexedCves === 3 && stats.kevCount === 2)

    console.log('\n[pocindex] 5. Version-audit enrichment, CVSS v4.0 authority & AI grounding')
    const finding = buildVersionFinding(
      { product: 'nginx', version: '1.18.0', kind: 'web-server', owasp: 'A03:2025-Software Supply Chain Failures', cwe: 'CWE-1104', source: 'header', matched: 'nginx/1.18.0' },
      {
        cves: [{ id: 'CVE-2024-9999', cvss: { score: 8.2, severity: 'HIGH', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N' }, description: 'Smuggling', weaknesses: ['CWE-444'], references: [] }],
        critical: 0, high: 1, medium: 0, total: 1,
      },
    )
    check('buildVersionFinding embeds pocindex enrichment in knownCves', Boolean(finding.evidence.knownCves[0].pocindex?.kev))
    const cvssEval = evaluateFindingCvss(finding)
    check('CVSS v4.0 scoring engine remains active and derives score cleanly', cvssEval.vector.startsWith('CVSS:4.0/') && cvssEval.score > 0)

    const aiCtx = buildCveIntelContext('Check remediation for CVE-2021-44228 immediately')
    check('AI context builder injects CISA KEV + EPSS + top PoC URL', aiCtx.includes('CVE-2021-44228') && aiCtx.includes('CISA KEV') && aiCtx.includes('log4j-shell-poc'))

    console.log('\n[pocindex] 6. Proactive re-correlation alerts & deduplication')
    const fakeFyp = new Database(fakeFypPath)
    fakeFyp.exec(`
      CREATE TABLE scans (id TEXT PRIMARY KEY, target TEXT, user_id TEXT, client TEXT);
      CREATE TABLE findings (id TEXT PRIMARY KEY, scan_id TEXT, title TEXT, cve_id TEXT, evidence TEXT, status TEXT);
      INSERT INTO scans VALUES ('scan_1', 'https://victim.example', 'usr_1', 'victim');
      INSERT INTO findings VALUES ('find_1', 'scan_1', 'Log4Shell RCE CVE-2021-44228', 'CVE-2021-44228', '{}', 'open');
    `)
    let sentBatches = []
    const corr1 = await correlateAndAlertFindings({
      fypDb: fakeFyp,
      notifier: async (matches) => sentBatches.push(matches),
    })
    check('first correlation dispatches KEV alert for open finding', corr1.matched === 1 && corr1.sent === 1 && sentBatches[0][0].kind === 'kev')

    const corr2 = await correlateAndAlertFindings({
      fypDb: fakeFyp,
      notifier: async (matches) => sentBatches.push(matches),
    })
    check('second correlation deduplicates already-notified finding cleanly', corr2.matched === 0 && corr2.sent === 0 && sentBatches.length === 1)
    fakeFyp.close()

    console.log(`\nALL POCINDEX TESTS PASS (${passed}/${passed})`)
  } finally {
    pocindexSync.stop()
    closePocindexDb()
    server.close()
    Object.assign(config.pocindex, prevPocConfig)
    try { fs.rmSync(tmpDir, { recursive: true, force: true }) } catch { /* ignore */ }
  }
}

runTests().catch((err) => {
  console.error('POCINDEX TEST FAILED:', err)
  process.exit(1)
})
