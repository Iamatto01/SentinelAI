import Database from 'better-sqlite3'
import fs from 'node:fs'
import path from 'node:path'
import { config } from '../config.js'

/**
 * Local PoC Index & Threat Intelligence store (`pocindex.db`).
 *
 * Mirrors 0xMarcio/pocindex feeds into a separate SQLite + FTS5 database so
 * 100+ MB of external PoC/EPSS/KEV/Nuclei metadata never bloats `fyp2.db`.
 * Note: upstream CVSS scores stored here are strictly reference metadata —
 * SentinelAI's CVSS v4.0 calculator (`cvss4.js`) remains the sole finding
 * scoring authority.
 */

let pocDb = null
let pocDbPath = null

// Short-lived in-memory cache for trending/stats feeds when DB is absent or warming up.
let trendingCache = { data: null, fetchedAt: 0 }
let statsCache = { data: null, fetchedAt: 0 }

const TRENDING_MEMORY_TTL_MS = 15 * 60 * 1000
const STATS_MEMORY_TTL_MS = 15 * 60 * 1000

const EXPECTED_TABLES = ['cves', 'cves_fts', 'repo_meta', 'sync_meta', 'feed_cache', 'notified_alerts']

export function resolvePocindexDbPath(customPath = null) {
  return customPath || config.pocindex?.dbPath || path.join(config.outputDir, 'pocindex.db')
}

export function initPocindexSchema(dbInstance, { withSecondaryIndexes = true } = {}) {
  dbInstance.exec(`
    CREATE TABLE IF NOT EXISTS sync_meta (
      feed TEXT PRIMARY KEY,
      etag TEXT,
      last_modified TEXT,
      last_checked_at TEXT,
      last_updated_at TEXT,
      item_count INTEGER DEFAULT 0,
      last_status INTEGER,
      last_error TEXT
    );

    CREATE TABLE IF NOT EXISTS cves (
      cve_id TEXT PRIMARY KEY,
      title TEXT DEFAULT '',
      desc TEXT DEFAULT '',
      vendor_json TEXT DEFAULT '[]',
      product_json TEXT DEFAULT '[]',
      vendor_text TEXT DEFAULT '',
      product_text TEXT DEFAULT '',
      published TEXT DEFAULT '',
      modified TEXT DEFAULT '',
      poc_json TEXT DEFAULT '[]',
      edb_json TEXT DEFAULT '[]',
      nuclei_json TEXT DEFAULT '[]',
      msf_json TEXT DEFAULT '[]',
      vulhub_json TEXT DEFAULT '[]',
      collections_json TEXT DEFAULT '[]',
      advisories_json TEXT DEFAULT '[]',
      cvss_json TEXT DEFAULT '[]',
      epss_score REAL,
      epss_percentile REAL,
      kev_added TEXT,
      kev_due TEXT,
      nuclei_severity TEXT,
      nuclei_cvss REAL,
      nuclei_vector TEXT,
      nuclei_cwe TEXT,
      max_cvss REAL,
      max_severity TEXT,
      top_stars INTEGER DEFAULT 0,
      poc_count INTEGER DEFAULT 0,
      source_count INTEGER DEFAULT 0,
      has_poc INTEGER DEFAULT 0,
      has_kev INTEGER DEFAULT 0,
      has_nuclei INTEGER DEFAULT 0,
      has_msf INTEGER DEFAULT 0,
      has_edb INTEGER DEFAULT 0,
      has_vulhub INTEGER DEFAULT 0,
      poc_observed INTEGER DEFAULT 0,
      metadata_pending INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS repo_meta (
      repo TEXT PRIMARY KEY,
      stars INTEGER DEFAULT 0,
      last_push TEXT DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS feed_cache (
      key TEXT PRIMARY KEY,
      data_json TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS notified_alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cve_id TEXT NOT NULL,
      finding_id TEXT NOT NULL,
      kind TEXT NOT NULL,
      notified_at TEXT NOT NULL,
      UNIQUE(cve_id, finding_id, kind)
    );

    CREATE VIRTUAL TABLE IF NOT EXISTS cves_fts USING fts5(
      cve_id,
      title,
      desc,
      vendor_text,
      product_text,
      content='cves',
      content_rowid='rowid',
      tokenize='unicode61'
    );
  `)

  if (withSecondaryIndexes) {
    createSecondaryIndexes(dbInstance)
  }
}

export function createSecondaryIndexes(dbInstance) {
  dbInstance.exec(`
    CREATE INDEX IF NOT EXISTS idx_cves_cvss ON cves(max_cvss DESC);
    CREATE INDEX IF NOT EXISTS idx_cves_epss ON cves(epss_score DESC);
    CREATE INDEX IF NOT EXISTS idx_cves_stars ON cves(top_stars DESC);
    CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published DESC);
    CREATE INDEX IF NOT EXISTS idx_cves_modified ON cves(modified DESC);
    CREATE INDEX IF NOT EXISTS idx_cves_kev ON cves(has_kev);
    CREATE INDEX IF NOT EXISTS idx_cves_nuclei ON cves(has_nuclei);
    CREATE INDEX IF NOT EXISTS idx_cves_msf ON cves(has_msf);
    CREATE INDEX IF NOT EXISTS idx_cves_edb ON cves(has_edb);
    CREATE INDEX IF NOT EXISTS idx_cves_vulhub ON cves(has_vulhub);
  `)
}

/**
 * Verify a candidate SQLite database satisfies AGENTS.md §3 predicates:
 * `integrity_check = 'ok'` AND all expected tables present.
 */
export function verifyPocindexDatabase(dbPath, { minCves = 0 } = {}) {
  if (!dbPath || !fs.existsSync(dbPath)) {
    return { ok: false, reason: 'file_missing', integrity: null, tableCount: 0, cveCount: 0 }
  }
  let probe = null
  try {
    probe = new Database(dbPath, { readonly: true, fileMustExist: true })
    const integrity = probe.pragma('integrity_check', { simple: true })
    const tables = probe.prepare(
      `SELECT name FROM sqlite_master WHERE type IN ('table', 'view')`
    ).pluck().all()
    const tableSet = new Set(tables)
    const missing = EXPECTED_TABLES.filter(t => !tableSet.has(t))
    let cveCount = 0
    if (tableSet.has('cves')) {
      cveCount = probe.prepare(`SELECT COUNT(*) FROM cves`).pluck().get() || 0
    }
    const ok = integrity === 'ok' && missing.length === 0 && cveCount >= minCves
    return {
      ok,
      integrity,
      tableCount: tables.length,
      missingTables: missing,
      cveCount,
      reason: ok ? null : (integrity !== 'ok' ? 'integrity_failed' : missing.length ? `missing_tables:${missing.join(',')}` : 'insufficient_cves'),
    }
  } catch (e) {
    return { ok: false, reason: e.message, integrity: null, tableCount: 0, cveCount: 0 }
  } finally {
    try { probe?.close() } catch { /* ignore */ }
  }
}

/**
 * Open or return the singleton read/write connection to `pocindex.db`.
 * Returns `null` when `createIfMissing` is false and the DB file is not ready yet.
 */
export function getPocindexDb({ createIfMissing = false, customPath = null } = {}) {
  const target = resolvePocindexDbPath(customPath)
  if (pocDb && pocDbPath === target) {
    try {
      if (pocDb.open) return pocDb
    } catch { /* reopen */ }
  }
  if (pocDb) closePocindexDb()

  if (!createIfMissing && !fs.existsSync(target)) return null
  fs.mkdirSync(path.dirname(target), { recursive: true })

  const d = new Database(target)
  d.pragma('journal_mode = WAL')
  d.pragma('busy_timeout = 5000')
  initPocindexSchema(d)
  pocDb = d
  pocDbPath = target
  return pocDb
}

export function closePocindexDb() {
  if (pocDb) {
    try { pocDb.close() } catch { /* ignore */ }
    pocDb = null
    pocDbPath = null
  }
}

/** Extract `owner/repo` slug from a GitHub URL for `repo_meta` star lookups. */
export function extractRepoSlug(url) {
  const m = String(url || '').match(/^https?:\/\/github\.com\/([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+?)(?:\.git|\/|$)/i)
  return m ? m[1] : null
}

function safeJsonParse(raw, fallback) {
  if (!raw) return fallback
  try { return JSON.parse(raw) } catch { return fallback }
}

/**
 * Build grouped PoC structure from a `cves` row, enriching GitHub URLs with
 * star count & last-push timestamps from `repo_meta`.
 */
export function formatGroupedPocs(row, dbInstance) {
  const pocUrls = safeJsonParse(row.poc_json, [])
  const edbUrls = safeJsonParse(row.edb_json, [])
  const nucleiUrls = safeJsonParse(row.nuclei_json, [])
  const msfUrls = safeJsonParse(row.msf_json, [])
  const vulhubUrls = safeJsonParse(row.vulhub_json, [])
  const collections = safeJsonParse(row.collections_json, [])

  let github = []
  if (pocUrls.length > 0 && dbInstance) {
    const stmt = dbInstance.prepare(`SELECT stars, last_push FROM repo_meta WHERE repo = ?`)
    github = pocUrls.map((url) => {
      const slug = extractRepoSlug(url)
      const meta = slug ? stmt.get(slug.toLowerCase()) : null
      return {
        url,
        repo: slug || null,
        stars: meta?.stars ?? 0,
        lastPush: meta?.last_push || null,
      }
    }).sort((a, b) => (b.stars || 0) - (a.stars || 0))
  } else {
    github = pocUrls.map((url) => ({ url, repo: extractRepoSlug(url), stars: 0, lastPush: null }))
  }

  return {
    github,
    edb: edbUrls,
    nuclei: nucleiUrls,
    msf: msfUrls,
    vulhub: vulhubUrls,
    collections,
  }
}

function serializeCveSummary(row, dbInstance, { maxPocs = 5 } = {}) {
  if (!row) return null
  const grouped = formatGroupedPocs(row, dbInstance)
  const vendors = safeJsonParse(row.vendor_json, [])
  const products = safeJsonParse(row.product_json, [])

  return {
    cveId: row.cve_id,
    title: row.title || null,
    description: row.desc || '',
    vendors,
    products,
    published: row.published || null,
    modified: row.modified || null,
    kev: row.has_kev ? { added: row.kev_added, due: row.kev_due || null } : null,
    epss: row.epss_score != null ? { score: row.epss_score, percentile: row.epss_percentile } : null,
    nuclei: row.has_nuclei ? {
      available: true,
      severity: row.nuclei_severity || null,
      cvss: row.nuclei_cvss ?? null,
      vector: row.nuclei_vector || null,
      cwe: row.nuclei_cwe || null,
      templates: grouped.nuclei,
    } : null,
    upstreamCvss: row.max_cvss != null ? { score: row.max_cvss, severity: row.max_severity } : null,
    topStars: row.top_stars || 0,
    pocCount: row.poc_count || 0,
    sourceCount: row.source_count || 0,
    hasPoc: Boolean(row.has_poc),
    pocObserved: Boolean(row.poc_observed),
    metadataPending: Boolean(row.metadata_pending),
    counts: {
      github: grouped.github.length,
      edb: grouped.edb.length,
      nuclei: grouped.nuclei.length,
      msf: grouped.msf.length,
      vulhub: grouped.vulhub.length,
      collections: grouped.collections.length,
    },
    pocs: {
      github: grouped.github.slice(0, maxPocs),
      edb: grouped.edb.slice(0, maxPocs),
      nuclei: grouped.nuclei.slice(0, maxPocs),
      msf: grouped.msf.slice(0, maxPocs),
      vulhub: grouped.vulhub.slice(0, maxPocs),
      collections: grouped.collections.slice(0, maxPocs),
    },
  }
}

/**
 * Parse a pocindex-style search query supporting quoted phrases and `-negation`.
 * Example: `apache "path traversal" -windows -wordpress`
 */
export function parseSearchQuery(rawQuery) {
  const q = String(rawQuery || '').trim()
  if (!q) return { positive: [], negative: [], raw: '' }

  const positive = []
  const negative = []
  const tokenRe = /(-?"[^"]+"|-?\S+)/g
  let m
  while ((m = tokenRe.exec(q)) !== null) {
    let tok = m[1]
    const isNeg = tok.startsWith('-')
    if (isNeg) tok = tok.slice(1)
    if (tok.startsWith('"') && tok.endsWith('"') && tok.length >= 2) {
      tok = tok.slice(1, -1)
    }
    tok = tok.trim()
    if (!tok) continue
    if (isNeg) negative.push(tok)
    else positive.push(tok)
  }
  return { positive, negative, raw: q }
}

function escapeFtsTerm(term) {
  // Split terms with hyphen/slash/dots cleanly into quoted phrase tokens or quote entire word
  const cleaned = String(term || '').replace(/"/g, '""').trim()
  if (!cleaned) return null
  return `"${cleaned}"`
}

function buildPositiveFtsMatch(positiveTerms) {
  const parts = positiveTerms.map(escapeFtsTerm).filter(Boolean)
  return parts.length ? parts.join(' AND ') : null
}

/**
 * Search the local PoC Index FTS5 store with filters & sorting.
 */
export function searchCves(query = '', filters = {}) {
  const dbInstance = getPocindexDb()
  const page = Math.max(1, parseInt(filters.page, 10) || 1)
  const limit = Math.min(100, Math.max(1, parseInt(filters.limit, 10) || 25))
  const offset = (page - 1) * limit

  if (!dbInstance) {
    return {
      available: false,
      total: 0,
      page,
      limit,
      totalPages: 0,
      items: [],
    }
  }

  const parsed = parseSearchQuery(query)
  const exactCveOnly =
    parsed.positive.length === 1 &&
    parsed.negative.length === 0 &&
    /^CVE-\d{4}-\d{4,}$/i.test(parsed.positive[0])

  const where = []
  const params = []
  let useFts = false
  let ftsMatch = null

  if (exactCveOnly) {
    where.push(`c.cve_id = ?`)
    params.push(parsed.positive[0].toUpperCase())
  } else if (parsed.positive.length > 0) {
    ftsMatch = buildPositiveFtsMatch(parsed.positive)
    if (ftsMatch) {
      if (parsed.negative.length > 0) {
        const negFts = parsed.negative.map(escapeFtsTerm).filter(Boolean)
        for (const nt of negFts) {
          ftsMatch += ` NOT ${nt}`
        }
      }
      useFts = true
      where.push(`cves_fts MATCH ?`)
      params.push(ftsMatch)
    }
  } else if (parsed.negative.length > 0) {
    // SQLite FTS5 rejects unary NOT without positive terms, so filter via LIKE cleanly.
    for (const neg of parsed.negative) {
      const pat = `%${neg.toLowerCase()}%`
      where.push(`(LOWER(c.title || ' ' || c.desc || ' ' || c.vendor_text || ' ' || c.product_text || ' ' || c.cve_id) NOT LIKE ?)`)
      params.push(pat)
    }
  }

  if (filters.kev === true || filters.kev === 'true' || filters.kev === '1' || filters.kev === 1) {
    where.push(`c.has_kev = 1`)
  }
  if (filters.hasPoc === true || filters.hasPoc === 'true' || filters.hasPoc === '1' || filters.hasPoc === 1) {
    where.push(`c.has_poc = 1`)
  }

  if (filters.severity) {
    const sev = String(filters.severity).toUpperCase().trim()
    if (sev === 'CRITICAL') where.push(`(UPPER(c.max_severity) = 'CRITICAL' OR c.max_cvss >= 9.0)`)
    else if (sev === 'HIGH') where.push(`(UPPER(c.max_severity) = 'HIGH' OR (c.max_cvss >= 7.0 AND c.max_cvss < 9.0))`)
    else if (sev === 'MEDIUM') where.push(`(UPPER(c.max_severity) = 'MEDIUM' OR (c.max_cvss >= 4.0 AND c.max_cvss < 7.0))`)
    else if (sev === 'LOW') where.push(`(UPPER(c.max_severity) = 'LOW' OR (c.max_cvss > 0 AND c.max_cvss < 4.0))`)
  }

  if (filters.source) {
    const src = String(filters.source).toLowerCase().trim()
    if (src === 'github') where.push(`c.poc_count > 0`)
    else if (src === 'edb' || src === 'exploitdb') where.push(`c.has_edb = 1`)
    else if (src === 'nuclei') where.push(`c.has_nuclei = 1`)
    else if (src === 'msf' || src === 'metasploit') where.push(`c.has_msf = 1`)
    else if (src === 'vulhub') where.push(`c.has_vulhub = 1`)
  }

  if (filters.year && /^\d{4}$/.test(String(filters.year).trim())) {
    where.push(`c.cve_id LIKE ?`)
    params.push(`CVE-${String(filters.year).trim()}-%`)
  }

  if (filters.minEpss != null && filters.minEpss !== '') {
    let minE = Number(filters.minEpss)
    if (Number.isFinite(minE)) {
      if (minE > 1) minE = minE / 100
      where.push(`c.epss_score >= ?`)
      params.push(minE)
    }
  }

  const fromSql = useFts
    ? `FROM cves_fts JOIN cves c ON c.rowid = cves_fts.rowid`
    : `FROM cves c`
  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : ''

  let orderSql = `ORDER BY COALESCE(c.max_cvss, 0) DESC, c.top_stars DESC`
  const sort = String(filters.sort || (useFts ? 'relevance' : 'modified')).toLowerCase()
  if (sort === 'relevance' && useFts) {
    orderSql = `ORDER BY bm25(cves_fts) ASC, c.has_kev DESC, COALESCE(c.epss_score, 0) DESC`
  } else if (sort === 'epss') {
    orderSql = `ORDER BY COALESCE(c.epss_score, -1) DESC, COALESCE(c.max_cvss, 0) DESC`
  } else if (sort === 'cvss') {
    orderSql = `ORDER BY COALESCE(c.max_cvss, -1) DESC, COALESCE(c.epss_score, 0) DESC`
  } else if (sort === 'stars') {
    orderSql = `ORDER BY c.top_stars DESC, c.source_count DESC`
  } else if (sort === 'pocs') {
    orderSql = `ORDER BY c.source_count DESC, c.top_stars DESC`
  } else if (sort === 'newest' || sort === 'published') {
    orderSql = `ORDER BY c.published DESC, c.cve_id DESC`
  } else if (sort === 'modified' || sort === 'recent') {
    orderSql = `ORDER BY c.modified DESC, c.published DESC`
  }

  try {
    const countRow = dbInstance.prepare(`SELECT COUNT(*) AS total ${fromSql} ${whereSql}`).get(...params)
    const total = countRow?.total || 0
    const rows = dbInstance.prepare(
      `SELECT c.* ${fromSql} ${whereSql} ${orderSql} LIMIT ? OFFSET ?`
    ).all(...params, limit, offset)

    return {
      available: true,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
      items: rows.map(r => serializeCveSummary(r, dbInstance)),
    }
  } catch (e) {
    return {
      available: true,
      total: 0,
      page,
      limit,
      totalPages: 0,
      items: [],
      error: e.message,
    }
  }
}

/** Full detail record for a single CVE from the local PoC Index. */
export function getCveDetail(cveId) {
  const id = String(cveId || '').toUpperCase().trim()
  if (!/^CVE-\d{4}-\d{4,}$/.test(id)) return null
  const dbInstance = getPocindexDb()
  if (!dbInstance) return null

  const row = dbInstance.prepare(`SELECT * FROM cves WHERE cve_id = ?`).get(id)
  if (!row) return null

  const summary = serializeCveSummary(row, dbInstance, { maxPocs: 50 })
  const cvssEntries = safeJsonParse(row.cvss_json, []).map((c) => {
    if (!Array.isArray(c)) return null
    return {
      version: c[0] || null,
      score: c[1] ?? null,
      severity: c[2] || null,
      vector: c[3] || null,
      source: c[4] || null,
      role: c[5] || null,
    }
  }).filter(Boolean)

  const advisories = safeJsonParse(row.advisories_json, []).map((a) => {
    if (!Array.isArray(a)) return null
    return { url: a[0] || null, tags: Array.isArray(a[1]) ? a[1] : [] }
  }).filter(Boolean)

  return {
    ...summary,
    cvssEntries,
    advisories,
  }
}

/**
 * Compact enrichment object for `cve.js`, `version-audit.js`, AI chat, and reports.
 * Never alters `cvss4.js` findings or scores.
 */
export function enrichCveWithPocindex(cveId, { maxPocs = 8 } = {}) {
  const id = String(cveId || '').toUpperCase().trim()
  if (!/^CVE-\d{4}-\d{4,}$/.test(id)) return null
  const dbInstance = getPocindexDb()
  if (!dbInstance) return null

  const row = dbInstance.prepare(`SELECT * FROM cves WHERE cve_id = ?`).get(id)
  if (!row) return null

  const grouped = formatGroupedPocs(row, dbInstance)
  return {
    inIndex: true,
    cveId: row.cve_id,
    kev: row.has_kev ? { added: row.kev_added, due: row.kev_due || null } : null,
    epss: row.epss_score != null ? { score: row.epss_score, percentile: row.epss_percentile } : null,
    nuclei: row.has_nuclei ? {
      available: true,
      severity: row.nuclei_severity || null,
      cvss: row.nuclei_cvss ?? null,
      cwe: row.nuclei_cwe || null,
      templates: grouped.nuclei.slice(0, maxPocs),
    } : null,
    upstreamCvss: row.max_cvss != null ? { score: row.max_cvss, severity: row.max_severity } : null,
    topStars: row.top_stars || 0,
    pocCount: row.poc_count || 0,
    sourceCount: row.source_count || 0,
    hasPoc: Boolean(row.has_poc),
    pocObserved: Boolean(row.poc_observed),
    counts: {
      github: grouped.github.length,
      edb: grouped.edb.length,
      nuclei: grouped.nuclei.length,
      msf: grouped.msf.length,
      vulhub: grouped.vulhub.length,
      collections: grouped.collections.length,
    },
    pocs: {
      github: grouped.github.slice(0, maxPocs),
      edb: grouped.edb.slice(0, maxPocs),
      nuclei: grouped.nuclei.slice(0, maxPocs),
      msf: grouped.msf.slice(0, maxPocs),
      vulhub: grouped.vulhub.slice(0, maxPocs),
      collections: grouped.collections.slice(0, maxPocs),
    },
  }
}

/** Look up top matched CVEs in local `pocindex.db` by product + optional version keyword. */
export function findProductPocsInIndex(product, version = '', { limit = 15 } = {}) {
  const term = [product, version].filter(Boolean).join(' ').trim()
  if (!term) return []
  const res = searchCves(term, { limit, sort: 'epss', hasPoc: true })
  return res.items || []
}

export function setMemoryFeedCache(key, data) {
  const entry = { data, fetchedAt: Date.now() }
  if (key === 'trending') trendingCache = entry
  else if (key === 'stats') statsCache = entry
}

function readFeedCacheFromDb(key) {
  const dbInstance = getPocindexDb()
  if (!dbInstance) return null
  try {
    const row = dbInstance.prepare(`SELECT data_json, updated_at FROM feed_cache WHERE key = ?`).get(key)
    if (!row) return null
    return { data: JSON.parse(row.data_json), updatedAt: row.updated_at }
  } catch {
    return null
  }
}

/** Return cached trending/just-landed feed, or fetch on-demand if uncached. */
export async function getTrending() {
  if (trendingCache.data && Date.now() - trendingCache.fetchedAt < TRENDING_MEMORY_TTL_MS) {
    return trendingCache.data
  }
  const fromDb = readFeedCacheFromDb('trending')
  if (fromDb?.data) {
    trendingCache = { data: fromDb.data, fetchedAt: Date.now() }
    return fromDb.data
  }
  const baseUrl = config.pocindex?.baseUrl || 'https://pocindex.io'
  try {
    const ctrl = new AbortController()
    const t = setTimeout(() => ctrl.abort(), 12000)
    const res = await fetch(`${baseUrl}/trending_poc.json`, {
      headers: { 'User-Agent': 'SentinelAI-PoCIndex/1.0' },
      signal: ctrl.signal,
    })
    clearTimeout(t)
    if (!res.ok) return { items: [], landed: [], error: `HTTP ${res.status}` }
    const json = await res.json()
    trendingCache = { data: json, fetchedAt: Date.now() }
    return json
  } catch (e) {
    return { items: [], landed: [], error: e.message }
  }
}

/** Return combined stats (local DB aggregates + upstream stats.json counts). */
export async function getPocindexStats() {
  const dbInstance = getPocindexDb()
  const dbStats = dbInstance ? dbInstance.prepare(`
    SELECT
      COUNT(*) AS indexedCves,
      SUM(CASE WHEN has_poc = 1 THEN 1 ELSE 0 END) AS withPocs,
      SUM(CASE WHEN has_kev = 1 THEN 1 ELSE 0 END) AS kevCount,
      SUM(CASE WHEN has_nuclei = 1 THEN 1 ELSE 0 END) AS nucleiCount,
      SUM(CASE WHEN has_msf = 1 THEN 1 ELSE 0 END) AS msfCount,
      SUM(CASE WHEN has_edb = 1 THEN 1 ELSE 0 END) AS edbCount,
      SUM(CASE WHEN has_vulhub = 1 THEN 1 ELSE 0 END) AS vulhubCount,
      SUM(poc_count) AS githubRepoLinks
    FROM cves
  `).get() : null

  let upstream = null
  if (statsCache.data && Date.now() - statsCache.fetchedAt < STATS_MEMORY_TTL_MS) {
    upstream = statsCache.data
  } else {
    const fromDb = readFeedCacheFromDb('stats')
    if (fromDb?.data) {
      upstream = fromDb.data
      statsCache = { data: upstream, fetchedAt: Date.now() }
    } else {
      const baseUrl = config.pocindex?.baseUrl || 'https://pocindex.io'
      try {
        const ctrl = new AbortController()
        const t = setTimeout(() => ctrl.abort(), 8000)
        const res = await fetch(`${baseUrl}/stats.json`, {
          headers: { 'User-Agent': 'SentinelAI-PoCIndex/1.0' },
          signal: ctrl.signal,
        })
        clearTimeout(t)
        if (res.ok) {
          upstream = await res.json()
          statsCache = { data: upstream, fetchedAt: Date.now() }
        }
      } catch { /* non-fatal */ }
    }
  }

  return {
    available: Boolean(dbInstance && (dbStats?.indexedCves || 0) > 0),
    indexedCves: dbStats?.indexedCves || 0,
    withPocs: dbStats?.withPocs || 0,
    kevCount: dbStats?.kevCount || 0,
    nucleiCount: dbStats?.nucleiCount || 0,
    msfCount: dbStats?.msfCount || 0,
    edbCount: dbStats?.edbCount || 0,
    vulhubCount: dbStats?.vulhubCount || 0,
    githubRepoLinks: dbStats?.githubRepoLinks || 0,
    upstream: upstream || null,
  }
}

export function getPocindexStatus() {
  const target = resolvePocindexDbPath()
  const exists = fs.existsSync(target)
  const dbInstance = getPocindexDb()
  let feeds = []
  let indexedCves = 0
  let kevCount = 0
  let sizeBytes = 0

  if (exists) {
    try { sizeBytes = fs.statSync(target).size } catch { sizeBytes = 0 }
  }
  if (dbInstance) {
    try {
      feeds = dbInstance.prepare(`SELECT * FROM sync_meta ORDER BY feed ASC`).all()
      const counts = dbInstance.prepare(`
        SELECT COUNT(*) AS indexedCves,
               SUM(CASE WHEN has_kev = 1 THEN 1 ELSE 0 END) AS kevCount
        FROM cves
      `).get()
      indexedCves = counts?.indexedCves || 0
      kevCount = counts?.kevCount || 0
    } catch { /* ignore */ }
  }

  return {
    enabled: config.pocindex?.enabled !== false,
    ready: Boolean(dbInstance && indexedCves > 0),
    dbExists: exists,
    dbPath: target,
    sizeBytes,
    indexedCves,
    kevCount,
    feeds,
  }
}

export default {
  resolvePocindexDbPath,
  initPocindexSchema,
  createSecondaryIndexes,
  verifyPocindexDatabase,
  getPocindexDb,
  closePocindexDb,
  extractRepoSlug,
  formatGroupedPocs,
  parseSearchQuery,
  searchCves,
  getCveDetail,
  enrichCveWithPocindex,
  findProductPocsInIndex,
  setMemoryFeedCache,
  getTrending,
  getPocindexStats,
  getPocindexStatus,
}
