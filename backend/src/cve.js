import * as db from './db.js'

/**
 * CVE lookup via the NIST NVD API v2, cached in SQLite (cve_cache) for 24h.
 * Replaces SentinelAI's local cvelistV5 git-clone (huge, not portable).
 * No API key required (rate-limited to ~5 req/30s without one).
 */

const NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
const TTL_MS = 24 * 60 * 60 * 1000

function parseNvd(cve) {
  const metrics = cve.metrics || {}
  const m =
    metrics.cvssMetricV31?.[0]?.cvssData ||
    metrics.cvssMetricV30?.[0]?.cvssData ||
    metrics.cvssMetricV2?.[0]?.cvssData || null
  const desc = cve.descriptions?.find((d) => d.lang === 'en')?.value || '(no description)'
  const weaknesses = (cve.weaknesses || []).flatMap((w) => w.description?.filter((d) => d.lang === 'en').map((d) => d.value) || [])
  const references = (cve.references || []).map((r) => r.url).filter(Boolean)
  return {
    id: cve.id,
    published: cve.published,
    lastModified: cve.lastModified,
    description: desc,
    cvss: m ? { score: m.baseScore, severity: m.baseSeverity || m.baseSeverity === undefined ? m.baseSeverity : null, vector: m.vectorString, version: m.version } : null,
    severity: m?.baseSeverity || null,
    weaknesses,
    references: references.slice(0, 12),
  }
}

export async function getCve(id) {
  const cveId = String(id || '').toUpperCase().trim()
  if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) return { error: 'invalid CVE id format' }

  const cached = db.get(`SELECT data, fetched_at FROM cve_cache WHERE id = ?`, cveId)
  if (cached && Date.now() - new Date(cached.fetched_at).getTime() < TTL_MS) {
    try { return { ...JSON.parse(cached.data), cached: true } } catch { /* fall through */ }
  }

  try {
    const ctrl = new AbortController()
    const t = setTimeout(() => ctrl.abort(), 12000)
    const res = await fetch(`${NVD}?cveId=${encodeURIComponent(cveId)}`, {
      headers: { 'User-Agent': 'fyp2-pentest-platform' },
      signal: ctrl.signal,
    })
    clearTimeout(t)
    if (res.status === 404) return { error: 'CVE not found' }
    if (!res.ok) return { error: `NVD HTTP ${res.status}` }
    const json = await res.json()
    const cve = json.vulnerabilities?.[0]?.cve
    if (!cve) return { error: 'CVE not found' }
    const parsed = parseNvd(cve)
    db.run(
      `INSERT INTO cve_cache (id, data, fetched_at) VALUES (?,?,?)
       ON CONFLICT(id) DO UPDATE SET data = excluded.data, fetched_at = excluded.fetched_at`,
      cveId, JSON.stringify(parsed), new Date().toISOString()
    )
    return parsed
  } catch (e) {
    return { error: e.name === 'AbortError' ? 'NVD request timed out' : e.message }
  }
}

/** Search NVD for an observed component/version. These are CVE candidates;
 * CPE applicability and installed version must be confirmed before reporting. */
export async function findVersionVulnerabilities(product, version) {
  const name = String(product || '').trim()
  const release = String(version || '').trim()
  if (!name || !release || name.length > 100 || release.length > 80) return { error: 'product and version are required' }
  const key = `version:${name.toLowerCase()}:${release.toLowerCase()}`
  const cached = db.get(`SELECT data, fetched_at FROM cve_cache WHERE id = ?`, key)
  if (cached && Date.now() - new Date(cached.fetched_at).getTime() < TTL_MS) {
    try { return { ...JSON.parse(cached.data), cached: true } } catch { /* refresh */ }
  }
  try {
    const params = new URLSearchParams({ keywordSearch: `${name} ${release}`, resultsPerPage: '20' })
      const ctrl = new AbortController()
      const t = setTimeout(() => ctrl.abort(), 15000)
      const res = await fetch(`${NVD}?${params}`, { headers: { 'User-Agent': 'fyp2-pentest-platform' }, signal: ctrl.signal })
      clearTimeout(t)
      if (!res.ok) return { error: `NVD HTTP ${res.status}` }
    const json = await res.json()
    const output = {
      product: name,
      version: release,
      applicability: 'needs-version-confirmation',
      results: (json.vulnerabilities || []).map((entry) => parseNvd(entry.cve)),
    }
    db.run(`INSERT INTO cve_cache (id, data, fetched_at) VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET data = excluded.data, fetched_at = excluded.fetched_at`, key, JSON.stringify(output), new Date().toISOString())
    return output
  } catch (error) { return { error: error.name === 'AbortError' ? 'NVD request timed out' : error.message } }
}

export default { getCve, findVersionVulnerabilities }
