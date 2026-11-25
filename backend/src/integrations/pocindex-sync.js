import Database from 'better-sqlite3'
import fs from 'node:fs'
import path from 'node:path'
import { config } from '../config.js'
import * as mainDb from '../db.js'
import {
  resolvePocindexDbPath,
  initPocindexSchema,
  createSecondaryIndexes,
  verifyPocindexDatabase,
  getPocindexDb,
  closePocindexDb,
  extractRepoSlug,
  setMemoryFeedCache,
} from './pocindex.js'

/**
 * ETag-driven background synchronizer & proactive alert correlator for `0xMarcio/pocindex`.
 *
 * Keeps `pocindex.db` fresh via two non-blocking `.unref()` timers:
 *   - Fast tick (default 1h): `stats.json` & `trending_poc.json`
 *   - Full tick (default 12h): `kev.json`, `epss.json`, `nuclei.json`,
 *     `repo_meta.json`, `CVE_list.json`, and `cve_metadata.json`
 *
 * Uses `If-None-Match` ETags so unchanged feeds return HTTP 304 with zero
 * re-download or rebuild overhead. Full builds write into a staging file and
 * pass `verifyPocindexDatabase()` (`integrity_check = 'ok'` + table count +
 * row count) before atomically replacing `pocindex.db`.
 */

let fastTimer = null
let fullTimer = null
let stopped = false

const syncState = {
  syncing: false,
  mode: null,
  startedAt: null,
  lastFinishedAt: null,
  lastSuccessAt: null,
  lastResult: null,
  lastError: null,
}

let channelNotifier = null

/** Register optional notification callback or channelGateway instance. */
export function setAlertNotifier(fn) {
  channelNotifier = fn
}

export function getSyncStatus() {
  const dbInstance = getPocindexDb()
  let feeds = []
  let dbReady = false
  let indexedCves = 0
  let kevCount = 0
  let dbLastSuccessAt = null
  if (dbInstance) {
    try {
      feeds = dbInstance.prepare(`SELECT * FROM sync_meta ORDER BY feed ASC`).all()
      const row = dbInstance.prepare(
        `SELECT COUNT(*) AS indexedCves, SUM(CASE WHEN has_kev = 1 THEN 1 ELSE 0 END) AS kevCount FROM cves`
      ).get()
      indexedCves = row?.indexedCves || 0
      kevCount = row?.kevCount || 0
      dbReady = indexedCves > 0
      const metaLatest = dbInstance.prepare(
        `SELECT MAX(last_updated_at) AS latest FROM sync_meta WHERE last_updated_at IS NOT NULL`
      ).get()
      dbLastSuccessAt = metaLatest?.latest || null
    } catch { /* ignore */ }
  }
  return {
    ...syncState,
    lastSuccessAt: syncState.lastSuccessAt || dbLastSuccessAt,
    dbReady,
    indexedCves,
    kevCount,
    dbPath: resolvePocindexDbPath(),
    baseUrl: config.pocindex?.baseUrl || 'https://pocindex.io',
    autoSync: config.pocindex?.autoSync !== false,
    fastIntervalMs: config.pocindex?.fastIntervalMs || 3600000,
    fullIntervalMs: config.pocindex?.fullIntervalMs || 43200000,
    feeds,
  }
}

/**
 * Incrementally stream top-level JSON objects from a ReadableStream holding `[ {...}, ... ]`.
 * Keeps heap overhead flat on ~52 MB payloads.
 */
export async function streamJsonArray(readableStream, onBatch, { batchSize = 1500 } = {}) {
  const reader = readableStream.getReader()
  const decoder = new TextDecoder('utf-8')
  let started = false
  let depth = 0
  let inString = false
  let escaped = false
  let objStart = -1
  let buf = ''
  let batch = []
  let total = 0

  const flush = async () => {
    if (!batch.length) return
    await onBatch(batch)
    batch = []
  }

  while (true) {
    const { value, done } = await reader.read()
    const chunk = done ? decoder.decode() : decoder.decode(value, { stream: true })
    if (chunk) {
      const startOffset = buf.length
      buf += chunk
      for (let i = startOffset; i < buf.length; i++) {
        const ch = buf[i]
        if (inString) {
          if (escaped) { escaped = false }
          else if (ch === '\\') { escaped = true }
          else if (ch === '"') { inString = false }
          continue
        }
        if (ch === '"') {
          inString = true
          continue
        }
        if (!started) {
          if (ch === '[') started = true
          continue
        }
        if (ch === '{') {
          if (depth === 0) objStart = i
          depth++
        } else if (ch === '}') {
          depth--
          if (depth === 0 && objStart !== -1) {
            const rawObj = buf.slice(objStart, i + 1)
            objStart = -1
            batch.push(JSON.parse(rawObj))
            total++
            if (batch.length >= batchSize) await flush()
          }
        }
      }
      if (depth === 0) {
        buf = ''
      } else if (objStart > 0) {
        buf = buf.slice(objStart)
        objStart = 0
      }
    }
    if (done) break
  }

  await flush()
  return total
}

/**
 * Incrementally stream top-level key/value pairs from `{ "CVE-...": {...}, ... }`.
 */
export async function streamJsonObjectEntries(readableStream, onBatch, { batchSize = 1500 } = {}) {
  const reader = readableStream.getReader()
  const decoder = new TextDecoder('utf-8')

  let state = 'WAIT_OPEN' // WAIT_OPEN | WAIT_KEY | READ_KEY | WAIT_COLON | WAIT_VAL | READ_VAL
  let escaped = false
  let inValString = false
  let valEscaped = false
  let valDepth = 0
  let tokenBuf = ''
  let currentKey = ''
  let batch = []
  let total = 0

  const flush = async () => {
    if (!batch.length) return
    await onBatch(batch)
    batch = []
  }

  const processChar = async (ch) => {
    switch (state) {
      case 'WAIT_OPEN':
        if (ch === '{') state = 'WAIT_KEY'
        return
      case 'WAIT_KEY':
        if (ch === '"') {
          tokenBuf = ''
          escaped = false
          state = 'READ_KEY'
        } else if (ch === '}') {
          state = 'DONE'
        }
        return
      case 'READ_KEY':
        if (escaped) {
          tokenBuf += '\\' + ch
          escaped = false
          return
        }
        if (ch === '\\') {
          escaped = true
          return
        }
        if (ch === '"') {
          currentKey = JSON.parse(`"${tokenBuf}"`)
          tokenBuf = ''
          state = 'WAIT_COLON'
          return
        }
        tokenBuf += ch
        return
      case 'WAIT_COLON':
        if (ch === ':') state = 'WAIT_VAL'
        return
      case 'WAIT_VAL':
        if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') return
        tokenBuf = ch
        inValString = ch === '"'
        valEscaped = false
        valDepth = (ch === '{' || ch === '[') ? 1 : 0
        state = 'READ_VAL'
        return
      case 'READ_VAL':
        if (inValString) {
          tokenBuf += ch
          if (valEscaped) valEscaped = false
          else if (ch === '\\') valEscaped = true
          else if (ch === '"') {
            inValString = false
            if (valDepth === 0) {
              batch.push([currentKey, JSON.parse(tokenBuf)])
              total++
              tokenBuf = ''
              state = 'WAIT_KEY'
              if (batch.length >= batchSize) await flush()
            }
          }
          return
        }
        if (valDepth > 0) {
          tokenBuf += ch
          if (ch === '"') {
            inValString = true
            valEscaped = false
          } else if (ch === '{' || ch === '[') {
            valDepth++
          } else if (ch === '}' || ch === ']') {
            valDepth--
            if (valDepth === 0) {
              batch.push([currentKey, JSON.parse(tokenBuf)])
              total++
              tokenBuf = ''
              state = 'WAIT_KEY'
              if (batch.length >= batchSize) await flush()
            }
          }
          return
        }
        // Primitive value at depth 0 (number, true, false, null)
        if (ch === ',' || ch === '}') {
          const val = JSON.parse(tokenBuf.trim())
          batch.push([currentKey, val])
          total++
          tokenBuf = ''
          state = ch === '}' ? 'DONE' : 'WAIT_KEY'
          if (batch.length >= batchSize) await flush()
        } else {
          tokenBuf += ch
        }
        return
      default:
        return
    }
  }

  while (true) {
    const { value, done } = await reader.read()
    const chunk = done ? decoder.decode() : decoder.decode(value, { stream: true })
    for (let i = 0; i < chunk.length; i++) {
      await processChar(chunk[i])
    }
    if (done) break
  }

  await flush()
  return total
}

function readExistingMeta(dbInstance) {
  const meta = new Map()
  if (!dbInstance) return meta
  try {
    const rows = dbInstance.prepare(`SELECT * FROM sync_meta`).all()
    for (const r of rows) meta.set(r.feed, r)
  } catch { /* ignore */ }
  return meta
}

async function fetchFeed(feedName, url, prevMeta, { force = false, stream = false, timeoutMs = 45000 } = {}) {
  const headers = { 'User-Agent': 'SentinelAI-PoCIndex/1.0' }
  if (!force && prevMeta?.etag) headers['If-None-Match'] = prevMeta.etag
  if (!force && !prevMeta?.etag && prevMeta?.last_modified) headers['If-Modified-Since'] = prevMeta.last_modified

  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    const res = await fetch(url, { headers, signal: ctrl.signal })
    clearTimeout(timer)
    if (res.status === 304) {
      return {
        feed: feedName,
        status: 304,
        unchanged: true,
        etag: prevMeta?.etag || null,
        lastModified: prevMeta?.last_modified || null,
      }
    }
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} for ${feedName}`)
    }
    const etag = res.headers.get('etag') || null
    const lastModified = res.headers.get('last-modified') || null
    if (stream) {
      return {
        feed: feedName,
        status: res.status,
        unchanged: false,
        etag,
        lastModified,
        res,
      }
    }
    const data = await res.json()
    return {
      feed: feedName,
      status: res.status,
      unchanged: false,
      etag,
      lastModified,
      data,
    }
  } catch (e) {
    clearTimeout(timer)
    throw new Error(`${feedName}: ${e.name === 'AbortError' ? 'request timed out' : e.message}`)
  }
}

function pickMaxCvss(cvssList) {
  if (!Array.isArray(cvssList) || !cvssList.length) return { score: null, severity: null }
  let best = null
  for (const item of cvssList) {
    if (!Array.isArray(item)) continue
    const score = Number(item[1])
    if (!Number.isFinite(score)) continue
    const role = String(item[5] || '')
    const ver = parseFloat(item[0] || '0') || 0
    if (
      !best ||
      (role === 'Primary' && best.role !== 'Primary') ||
      (role === best.role && ver > best.ver) ||
      (role === best.role && ver === best.ver && score > best.score)
    ) {
      best = { score, severity: item[2] ? String(item[2]).toUpperCase() : null, role, ver }
    }
  }
  return best ? { score: best.score, severity: best.severity } : { score: null, severity: null }
}

function upsertSyncMeta(dbInstance, records) {
  const stmt = dbInstance.prepare(`
    INSERT INTO sync_meta (feed, etag, last_modified, last_checked_at, last_updated_at, item_count, last_status, last_error)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(feed) DO UPDATE SET
      etag = COALESCE(excluded.etag, sync_meta.etag),
      last_modified = COALESCE(excluded.last_modified, sync_meta.last_modified),
      last_checked_at = excluded.last_checked_at,
      last_updated_at = COALESCE(excluded.last_updated_at, sync_meta.last_updated_at),
      item_count = CASE WHEN excluded.item_count >= 0 THEN excluded.item_count ELSE sync_meta.item_count END,
      last_status = excluded.last_status,
      last_error = excluded.last_error
  `)
  const tx = dbInstance.transaction(() => {
    for (const r of records) {
      stmt.run(
        r.feed,
        r.etag ?? null,
        r.lastModified ?? null,
        r.lastCheckedAt,
        r.lastUpdatedAt ?? null,
        r.itemCount ?? -1,
        r.lastStatus ?? null,
        r.lastError ?? null
      )
    }
  })
  tx()
}

function writeFeedCache(dbInstance, key, data, nowIso) {
  if (!dbInstance || !data) return
  dbInstance.prepare(`
    INSERT INTO feed_cache (key, data_json, updated_at) VALUES (?, ?, ?)
    ON CONFLICT(key) DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at
  `).run(key, JSON.stringify(data), nowIso)
}

function removeWalSidecars(dbPath) {
  for (const suffix of ['-wal', '-shm', '-journal']) {
    try {
      if (fs.existsSync(dbPath + suffix)) fs.unlinkSync(dbPath + suffix)
    } catch { /* ignore */ }
  }
}

function swapStagingFile(stagingPath, targetPath) {
  closePocindexDb()
  removeWalSidecars(targetPath)
  try {
    fs.renameSync(stagingPath, targetPath)
  } catch {
    // Windows fallback when antivirus/indexer briefly holds handle
    fs.copyFileSync(stagingPath, targetPath)
    try { fs.unlinkSync(stagingPath) } catch { /* ignore */ }
  }
  removeWalSidecars(stagingPath)
}

/**
 * Sync PoC Index feeds into `pocindex.db`.
 * Supports ETag conditional requests, full staging builds, and delta updates.
 */
export async function syncNow({ force = false, full = true } = {}) {
  if (config.pocindex?.enabled === false) {
    return { ok: false, skipped: true, reason: 'pocindex disabled' }
  }
  if (syncState.syncing) {
    return { ok: true, skipped: true, reason: 'sync already in progress' }
  }

  const baseUrl = config.pocindex?.baseUrl || 'https://pocindex.io'
  const targetPath = resolvePocindexDbPath()
  const stagingPath = `${targetPath}.staging`
  const nowIso = new Date().toISOString()

  syncState.syncing = true
  syncState.mode = full ? 'full' : 'fast'
  syncState.startedAt = nowIso
  syncState.lastError = null

  const metaUpdates = []
  let fastStatsData = null
  let fastTrendingData = null

  try {
    const existingDb = getPocindexDb()
    const dbExists = Boolean(existingDb && verifyPocindexDatabase(targetPath, { minCves: 1 }).ok)
    const prevMeta = dbExists ? readExistingMeta(existingDb) : new Map()

    // 1. Fast feeds (`stats.json` & `trending_poc.json`)
    try {
      const statsRes = await fetchFeed('stats', `${baseUrl}/stats.json`, prevMeta.get('stats'), { force: force || !dbExists, timeoutMs: 12000 })
      if (!statsRes.unchanged && statsRes.data) {
        fastStatsData = statsRes.data
        setMemoryFeedCache('stats', fastStatsData)
      }
      metaUpdates.push({
        feed: 'stats',
        etag: statsRes.etag,
        lastModified: statsRes.lastModified,
        lastCheckedAt: nowIso,
        lastUpdatedAt: statsRes.unchanged ? null : nowIso,
        itemCount: fastStatsData?.total_cves ?? -1,
        lastStatus: statsRes.status,
      })
    } catch (e) {
      metaUpdates.push({ feed: 'stats', lastCheckedAt: nowIso, itemCount: -1, lastStatus: 0, lastError: e.message })
    }

    try {
      const trendingRes = await fetchFeed('trending', `${baseUrl}/trending_poc.json`, prevMeta.get('trending'), { force: force || !dbExists, timeoutMs: 15000 })
      if (!trendingRes.unchanged && trendingRes.data) {
        fastTrendingData = trendingRes.data
        setMemoryFeedCache('trending', fastTrendingData)
      }
      metaUpdates.push({
        feed: 'trending',
        etag: trendingRes.etag,
        lastModified: trendingRes.lastModified,
        lastCheckedAt: nowIso,
        lastUpdatedAt: trendingRes.unchanged ? null : nowIso,
        itemCount: fastTrendingData ? (fastTrendingData.items?.length || 0) + (fastTrendingData.landed?.length || 0) : -1,
        lastStatus: trendingRes.status,
      })
    } catch (e) {
      metaUpdates.push({ feed: 'trending', lastCheckedAt: nowIso, itemCount: -1, lastStatus: 0, lastError: e.message })
    }

    if (!full && dbExists) {
      writeFeedCache(existingDb, 'stats', fastStatsData, nowIso)
      writeFeedCache(existingDb, 'trending', fastTrendingData, nowIso)
      upsertSyncMeta(existingDb, metaUpdates)
      const res = { ok: true, mode: 'fast', updated: Boolean(fastStatsData || fastTrendingData) }
      syncState.lastResult = res
      syncState.lastSuccessAt = nowIso
      return res
    }

    // 2. Full / delta feeds
    const needFreshBuild = !dbExists || force

    // Small maps first
    const smallDefs = [
      { name: 'kev', path: '/kev.json', timeoutMs: 15000 },
      { name: 'nuclei', path: '/nuclei.json', timeoutMs: 25000 },
      { name: 'repo_meta', path: '/repo_meta.json', timeoutMs: 30000 },
      { name: 'epss', path: '/epss.json', timeoutMs: 45000 },
    ]
    const smallResults = {}
    for (const s of smallDefs) {
      const r = await fetchFeed(s.name, `${baseUrl}${s.path}`, prevMeta.get(s.name), {
        force: needFreshBuild,
        timeoutMs: s.timeoutMs,
      })
      smallResults[s.name] = r
      metaUpdates.push({
        feed: s.name,
        etag: r.etag,
        lastModified: r.lastModified,
        lastCheckedAt: nowIso,
        lastUpdatedAt: r.unchanged ? null : nowIso,
        itemCount: !r.unchanged && r.data ? Object.keys(r.data).length : -1,
        lastStatus: r.status,
      })
    }

    // Large CVE_list.json stream probe
    const cveListRes = await fetchFeed('CVE_list', `${baseUrl}/CVE_list.json`, prevMeta.get('CVE_list'), {
      force: needFreshBuild,
      stream: true,
      timeoutMs: 120000,
    })

    const rebuildingFromScratch = needFreshBuild || !cveListRes.unchanged

    // Fetch cve_metadata.json (always if rebuilding from scratch & unchanged was not requested, or conditional if delta)
    const cveMetaRes = await fetchFeed('cve_metadata', `${baseUrl}/cve_metadata.json`, prevMeta.get('cve_metadata'), {
      force: rebuildingFromScratch,
      stream: true,
      timeoutMs: 120000,
    })

    // Ensure if rebuildingFromScratch due to CVE_list change on an existing DB, any small feed that came back 304 is re-fetched cleanly
    if (rebuildingFromScratch) {
      for (const s of smallDefs) {
        if (smallResults[s.name]?.unchanged) {
          const refreshed = await fetchFeed(s.name, `${baseUrl}${s.path}`, null, { force: true, timeoutMs: s.timeoutMs })
          smallResults[s.name] = refreshed
          const metaEntry = metaUpdates.find(m => m.feed === s.name)
          if (metaEntry && refreshed.data) {
            metaEntry.itemCount = Object.keys(refreshed.data).length
            metaEntry.lastStatus = refreshed.status
          }
        }
      }
    }

    const anyFullChanged =
      rebuildingFromScratch ||
      !cveMetaRes.unchanged ||
      Object.values(smallResults).some(r => !r.unchanged)

    if (!anyFullChanged && dbExists) {
      metaUpdates.push(
        {
          feed: 'CVE_list',
          etag: cveListRes.etag,
          lastModified: cveListRes.lastModified,
          lastCheckedAt: nowIso,
          itemCount: -1,
          lastStatus: 304,
        },
        {
          feed: 'cve_metadata',
          etag: cveMetaRes.etag,
          lastModified: cveMetaRes.lastModified,
          lastCheckedAt: nowIso,
          itemCount: -1,
          lastStatus: 304,
        }
      )
      writeFeedCache(existingDb, 'stats', fastStatsData, nowIso)
      writeFeedCache(existingDb, 'trending', fastTrendingData, nowIso)
      upsertSyncMeta(existingDb, metaUpdates)
      const res = { ok: true, mode: 'full', updated: false, message: 'All feeds unchanged (304 Not Modified)' }
      syncState.lastResult = res
      syncState.lastSuccessAt = nowIso
      return res
    }

    // Prepare staging database
    fs.mkdirSync(path.dirname(stagingPath), { recursive: true })
    if (fs.existsSync(stagingPath)) fs.unlinkSync(stagingPath)
    removeWalSidecars(stagingPath)

    let indexedCount = 0
    let metaAppliedCount = 0
    const updatedKevIds = []
    const newPocCveIds = []

    if (rebuildingFromScratch) {
      const staging = new Database(stagingPath)
      staging.pragma('journal_mode = WAL')
      staging.pragma('synchronous = OFF')
      staging.pragma('temp_store = MEMORY')
      initPocindexSchema(staging, { withSecondaryIndexes: false })

      // Preserve notified alert ledger & previous feed cache if rebuilding on top of live DB
      if (dbExists && existingDb) {
        try {
          const alerts = existingDb.prepare(`SELECT cve_id, finding_id, kind, notified_at FROM notified_alerts`).all()
          const insAlert = staging.prepare(`INSERT OR IGNORE INTO notified_alerts (cve_id, finding_id, kind, notified_at) VALUES (?,?,?,?)`)
          const txA = staging.transaction(() => { for (const a of alerts) insAlert.run(a.cve_id, a.finding_id, a.kind, a.notified_at) })
          txA()
        } catch { /* ignore */ }
        try {
          const caches = existingDb.prepare(`SELECT key, data_json, updated_at FROM feed_cache`).all()
          const insCache = staging.prepare(`INSERT OR IGNORE INTO feed_cache (key, data_json, updated_at) VALUES (?,?,?)`)
          const txC = staging.transaction(() => { for (const c of caches) insCache.run(c.key, c.data_json, c.updated_at) })
          txC()
        } catch { /* ignore */ }
      }

      const kevData = smallResults.kev.data || {}
      const epssData = smallResults.epss.data || {}
      const nucleiData = smallResults.nuclei.data || {}
      const repoMetaRaw = smallResults.repo_meta.data || {}

      // Normalize repo_meta by lowercased slug for case-insensitive matching
      const repoStars = new Map()
      const insRepo = staging.prepare(`INSERT OR REPLACE INTO repo_meta (repo, stars, last_push) VALUES (?, ?, ?)`)
      const txRepos = staging.transaction(() => {
        for (const [slug, arr] of Object.entries(repoMetaRaw)) {
          const norm = String(slug).toLowerCase()
          const stars = Array.isArray(arr) ? (Number(arr[0]) || 0) : 0
          const lastPush = Array.isArray(arr) && arr[1] ? String(arr[1]) : ''
          repoStars.set(norm, { stars, lastPush })
          insRepo.run(norm, stars, lastPush)
        }
      })
      txRepos()

      // Collect which KEV & PoC IDs changed compared to previous DB so proactive alerting knows what's new
      let prevKevSet = null
      let prevPocSet = null
      if (dbExists && existingDb) {
        try {
          prevKevSet = new Set(existingDb.prepare(`SELECT cve_id FROM cves WHERE has_kev = 1`).pluck().all())
          prevPocSet = new Set(existingDb.prepare(`SELECT cve_id FROM cves WHERE has_poc = 1`).pluck().all())
        } catch { /* ignore */ }
      }

      const insertCve = staging.prepare(`
        INSERT OR REPLACE INTO cves (
          cve_id, title, desc, vendor_json, product_json, vendor_text, product_text,
          published, modified, poc_json, edb_json, nuclei_json, msf_json, vulhub_json, collections_json,
          epss_score, epss_percentile, kev_added, kev_due,
          nuclei_severity, nuclei_cvss, nuclei_vector, nuclei_cwe,
          top_stars, poc_count, source_count,
          has_poc, has_kev, has_nuclei, has_msf, has_edb, has_vulhub,
          poc_observed, metadata_pending
        ) VALUES (
          ?,?,?,?,?,?,?,
          ?,?,?,?,?,?,?,?,
          ?,?,?,?,
          ?,?,?,?,
          ?,?,?,
          ?,?,?,?,?,?,
          ?,?
        )
      `)

      indexedCount = await streamJsonArray(cveListRes.res.body, (batch) => {
        const tx = staging.transaction(() => {
          for (const item of batch) {
            const cveId = String(item?.cve || '').toUpperCase().trim()
            if (!cveId) continue
            const pocs = Array.isArray(item.poc) ? item.poc : []
            const edb = Array.isArray(item.edb) ? item.edb : []
            const nuclei = Array.isArray(item.nuclei) ? item.nuclei : []
            const msf = Array.isArray(item.msf) ? item.msf : []
            const vulhub = Array.isArray(item.vulhub) ? item.vulhub : []
            const collections = Array.isArray(item.collections) ? item.collections : []
            const vendors = Array.isArray(item.vendor) ? item.vendor : []
            const products = Array.isArray(item.product) ? item.product : []

            let topStars = 0
            for (const url of pocs) {
              const slug = extractRepoSlug(url)
              const meta = slug ? repoStars.get(slug.toLowerCase()) : null
              if (meta && meta.stars > topStars) topStars = meta.stars
            }

            const kevRow = kevData[cveId]
            const epssRow = epssData[cveId]
            const nucleiRow = nucleiData[cveId]

            const sourceCount = pocs.length + edb.length + nuclei.length + msf.length + vulhub.length + collections.length
            const hasPoc = sourceCount > 0 ? 1 : 0
            const hasKev = kevRow ? 1 : 0
            const hasNuclei = (nuclei.length > 0 || Boolean(nucleiRow)) ? 1 : 0

            if (hasKev && (!prevKevSet || !prevKevSet.has(cveId))) updatedKevIds.push(cveId)
            if (hasPoc && (!prevPocSet || !prevPocSet.has(cveId))) newPocCveIds.push(cveId)

            insertCve.run(
              cveId,
              item.title ? String(item.title) : '',
              item.desc ? String(item.desc) : '',
              JSON.stringify(vendors),
              JSON.stringify(products),
              vendors.join(' '),
              products.join(' '),
              item.published ? String(item.published) : '',
              item.modified ? String(item.modified) : '',
              JSON.stringify(pocs),
              JSON.stringify(edb),
              JSON.stringify(nuclei),
              JSON.stringify(msf),
              JSON.stringify(vulhub),
              JSON.stringify(collections),
              Array.isArray(epssRow) ? Number(epssRow[0]) : null,
              Array.isArray(epssRow) ? Number(epssRow[1]) : null,
              Array.isArray(kevRow) ? String(kevRow[0]) : null,
              Array.isArray(kevRow) && kevRow[1] ? String(kevRow[1]) : null,
              nucleiRow?.severity ? String(nucleiRow.severity) : null,
              nucleiRow?.cvss != null ? Number(nucleiRow.cvss) : null,
              nucleiRow?.cvss_vector ? String(nucleiRow.cvss_vector) : null,
              nucleiRow?.cwe ? String(nucleiRow.cwe) : null,
              topStars,
              pocs.length,
              sourceCount,
              hasPoc,
              hasKev,
              hasNuclei,
              msf.length > 0 ? 1 : 0,
              edb.length > 0 ? 1 : 0,
              vulhub.length > 0 ? 1 : 0,
              item.poc_observed ? 1 : 0,
              item.metadata_pending ? 1 : 0
            )
          }
        })
        tx()
      }, { batchSize: 2000 })

      if (!cveMetaRes.unchanged && cveMetaRes.res?.body) {
        const updateMetaStmt = staging.prepare(`
          UPDATE cves SET
            cvss_json = ?,
            advisories_json = ?,
            max_cvss = ?,
            max_severity = ?
          WHERE cve_id = ?
        `)
        metaAppliedCount = await streamJsonObjectEntries(cveMetaRes.res.body, (batch) => {
          const tx = staging.transaction(() => {
            for (const [id, entry] of batch) {
              const cveId = String(id || '').toUpperCase().trim()
              if (!cveId || !entry || typeof entry !== 'object') continue
              const cvss = Array.isArray(entry.cvss) ? entry.cvss : []
              const advisories = Array.isArray(entry.advisories) ? entry.advisories : []
              const max = pickMaxCvss(cvss)
              updateMetaStmt.run(
                JSON.stringify(cvss),
                JSON.stringify(advisories),
                max.score,
                max.severity,
                cveId
              )
            }
          })
          tx()
        }, { batchSize: 2000 })
      }

      createSecondaryIndexes(staging)
      staging.exec(`INSERT INTO cves_fts(cves_fts) VALUES('rebuild');`)

      metaUpdates.push(
        {
          feed: 'CVE_list',
          etag: cveListRes.etag,
          lastModified: cveListRes.lastModified,
          lastCheckedAt: nowIso,
          lastUpdatedAt: nowIso,
          itemCount: indexedCount,
          lastStatus: cveListRes.status,
        },
        {
          feed: 'cve_metadata',
          etag: cveMetaRes.etag,
          lastModified: cveMetaRes.lastModified,
          lastCheckedAt: nowIso,
          lastUpdatedAt: cveMetaRes.unchanged ? null : nowIso,
          itemCount: metaAppliedCount,
          lastStatus: cveMetaRes.status,
        }
      )
      writeFeedCache(staging, 'stats', fastStatsData, nowIso)
      writeFeedCache(staging, 'trending', fastTrendingData, nowIso)
      upsertSyncMeta(staging, metaUpdates)

      staging.pragma('wal_checkpoint(TRUNCATE)')
      staging.pragma('journal_mode = DELETE')
      staging.close()
    } else {
      // Delta update onto a verified SQLite backup copy of existing `pocindex.db`
      await existingDb.backup(stagingPath)
      const staging = new Database(stagingPath)
      staging.pragma('journal_mode = WAL')
      staging.pragma('busy_timeout = 5000')
      initPocindexSchema(staging)

      indexedCount = staging.prepare(`SELECT COUNT(*) FROM cves`).pluck().get() || 0

      if (!smallResults.kev.unchanged && smallResults.kev.data) {
        const prevKevSet = new Set(staging.prepare(`SELECT cve_id FROM cves WHERE has_kev = 1`).pluck().all())
        const clearStmt = staging.prepare(`UPDATE cves SET has_kev = 0, kev_added = NULL, kev_due = NULL WHERE has_kev = 1`)
        const setStmt = staging.prepare(`UPDATE cves SET has_kev = 1, kev_added = ?, kev_due = ? WHERE cve_id = ?`)
        const tx = staging.transaction(() => {
          clearStmt.run()
          for (const [id, row] of Object.entries(smallResults.kev.data)) {
            const cveId = id.toUpperCase()
            if (!prevKevSet.has(cveId)) updatedKevIds.push(cveId)
            setStmt.run(
              Array.isArray(row) ? String(row[0]) : null,
              Array.isArray(row) && row[1] ? String(row[1]) : null,
              cveId
            )
          }
        })
        tx()
      }

      if (!smallResults.epss.unchanged && smallResults.epss.data) {
        const stmt = staging.prepare(`UPDATE cves SET epss_score = ?, epss_percentile = ? WHERE cve_id = ?`)
        const tx = staging.transaction(() => {
          for (const [id, row] of Object.entries(smallResults.epss.data)) {
            if (!Array.isArray(row)) continue
            stmt.run(Number(row[0]), Number(row[1]), id.toUpperCase())
          }
        })
        tx()
      }

      if (!smallResults.nuclei.unchanged && smallResults.nuclei.data) {
        const stmt = staging.prepare(`
          UPDATE cves SET
            has_nuclei = 1,
            nuclei_severity = ?,
            nuclei_cvss = ?,
            nuclei_vector = ?,
            nuclei_cwe = ?
          WHERE cve_id = ?
        `)
        const tx = staging.transaction(() => {
          for (const [id, row] of Object.entries(smallResults.nuclei.data)) {
            stmt.run(
              row?.severity ? String(row.severity) : null,
              row?.cvss != null ? Number(row.cvss) : null,
              row?.cvss_vector ? String(row.cvss_vector) : null,
              row?.cwe ? String(row.cwe) : null,
              id.toUpperCase()
            )
          }
        })
        tx()
      }

      if (!smallResults.repo_meta.unchanged && smallResults.repo_meta.data) {
        const repoStars = new Map()
        const insRepo = staging.prepare(`INSERT OR REPLACE INTO repo_meta (repo, stars, last_push) VALUES (?, ?, ?)`)
        const txRepo = staging.transaction(() => {
          for (const [slug, arr] of Object.entries(smallResults.repo_meta.data)) {
            const norm = slug.toLowerCase()
            const stars = Array.isArray(arr) ? (Number(arr[0]) || 0) : 0
            const lastPush = Array.isArray(arr) && arr[1] ? String(arr[1]) : ''
            repoStars.set(norm, stars)
            insRepo.run(norm, stars, lastPush)
          }
        })
        txRepo()

        const rows = staging.prepare(`SELECT cve_id, poc_json, top_stars FROM cves WHERE poc_count > 0`).all()
        const updStar = staging.prepare(`UPDATE cves SET top_stars = ? WHERE cve_id = ?`)
        const txStars = staging.transaction(() => {
          for (const r of rows) {
            let pocs = []
            try { pocs = JSON.parse(r.poc_json || '[]') } catch { pocs = [] }
            let best = 0
            for (const url of pocs) {
              const slug = extractRepoSlug(url)
              const st = slug ? repoStars.get(slug.toLowerCase()) : 0
              if (st && st > best) best = st
            }
            if (best !== (r.top_stars || 0)) updStar.run(best, r.cve_id)
          }
        })
        txStars()
      }

      if (!cveMetaRes.unchanged && cveMetaRes.res?.body) {
        const updateMetaStmt = staging.prepare(`
          UPDATE cves SET cvss_json = ?, advisories_json = ?, max_cvss = ?, max_severity = ? WHERE cve_id = ?
        `)
        metaAppliedCount = await streamJsonObjectEntries(cveMetaRes.res.body, (batch) => {
          const tx = staging.transaction(() => {
            for (const [id, entry] of batch) {
              const cveId = String(id || '').toUpperCase().trim()
              if (!cveId || !entry || typeof entry !== 'object') continue
              const cvss = Array.isArray(entry.cvss) ? entry.cvss : []
              const advisories = Array.isArray(entry.advisories) ? entry.advisories : []
              const max = pickMaxCvss(cvss)
              updateMetaStmt.run(JSON.stringify(cvss), JSON.stringify(advisories), max.score, max.severity, cveId)
            }
          })
          tx()
        }, { batchSize: 2000 })
      }

      metaUpdates.push(
        { feed: 'CVE_list', lastCheckedAt: nowIso, itemCount: -1, lastStatus: 304 },
        {
          feed: 'cve_metadata',
          etag: cveMetaRes.etag,
          lastModified: cveMetaRes.lastModified,
          lastCheckedAt: nowIso,
          lastUpdatedAt: cveMetaRes.unchanged ? null : nowIso,
          itemCount: metaAppliedCount || -1,
          lastStatus: cveMetaRes.status,
        }
      )
      writeFeedCache(staging, 'stats', fastStatsData, nowIso)
      writeFeedCache(staging, 'trending', fastTrendingData, nowIso)
      upsertSyncMeta(staging, metaUpdates)

      staging.pragma('wal_checkpoint(TRUNCATE)')
      staging.pragma('journal_mode = DELETE')
      staging.close()
    }

    // AGENTS.md §3 verification predicate before swap
    const verification = verifyPocindexDatabase(stagingPath, { minCves: 1 })
    if (!verification.ok) {
      try { if (fs.existsSync(stagingPath)) fs.unlinkSync(stagingPath) } catch { /* ignore */ }
      throw new Error(`Staging verification failed (${verification.reason})`)
    }

    swapStagingFile(stagingPath, targetPath)
    const live = getPocindexDb()

    // Trigger proactive re-correlation alerts for new KEV/PoC updates matching historical findings
    let alertSummary = { matched: 0, sent: 0 }
    try {
      alertSummary = await correlateAndAlertFindings({
        pocDb: live,
        onlyCveIds: updatedKevIds.length || newPocCveIds.length ? new Set([...updatedKevIds, ...newPocCveIds]) : null,
      })
    } catch (e) {
      console.warn(`[pocindex] Proactive correlation skipped: ${e.message}`)
    }

    const res = {
      ok: true,
      mode: rebuildingFromScratch ? 'full-rebuild' : 'delta',
      updated: true,
      indexedCves: verification.cveCount,
      metaAppliedCount,
      newKevMatches: updatedKevIds.length,
      newPocMatches: newPocCveIds.length,
      alertsSent: alertSummary.sent,
    }
    syncState.lastResult = res
    syncState.lastSuccessAt = nowIso
    return res
  } catch (e) {
    try { if (fs.existsSync(stagingPath)) fs.unlinkSync(stagingPath) } catch { /* ignore */ }
    removeWalSidecars(stagingPath)
    syncState.lastError = e.message
    console.warn(`[pocindex-sync] Sync failed (keeping existing DB intact): ${e.message}`)
    return { ok: false, error: e.message }
  } finally {
    syncState.syncing = false
    syncState.mode = null
    syncState.lastFinishedAt = new Date().toISOString()
  }
}

/**
 * Compare updated KEV / public-PoC CVEs against existing scan findings in `fyp2.db`
 * (strictly read-only on `fyp2.db`), deduplicating via `notified_alerts` in `pocindex.db`.
 */
export async function correlateAndAlertFindings({ pocDb = null, fypDb = null, onlyCveIds = null, notifier = null } = {}) {
  const indexDb = pocDb || getPocindexDb()
  if (!indexDb) return { matched: 0, sent: 0 }

  let rows = []
  try {
    const sql = `
      SELECT f.id AS finding_id, f.scan_id, f.title, f.cve_id, f.evidence,
             s.target, s.user_id, s.client
      FROM findings f
      JOIN scans s ON f.scan_id = s.id
      WHERE f.status NOT IN ('fixed', 'false-positive')
    `
    rows = fypDb ? fypDb.prepare(sql).all() : mainDb.all(sql)
  } catch {
    return { matched: 0, sent: 0 }
  }
  if (!rows.length) return { matched: 0, sent: 0 }

  const candidateMatches = []
  const cveLookupStmt = indexDb.prepare(`SELECT cve_id, has_kev, kev_added, has_poc, source_count, epss_score, top_stars FROM cves WHERE cve_id = ?`)
  const alreadySentStmt = indexDb.prepare(`SELECT 1 FROM notified_alerts WHERE cve_id = ? AND finding_id = ? AND kind = ?`)
  const recordSentStmt = indexDb.prepare(`INSERT OR IGNORE INTO notified_alerts (cve_id, finding_id, kind, notified_at) VALUES (?, ?, ?, ?)`)

  const cveRegex = /CVE-\d{4}-\d{4,}/gi

  for (const row of rows) {
    const foundCves = new Set()
    if (row.cve_id) foundCves.add(String(row.cve_id).toUpperCase().trim())
    const titleMatches = String(row.title || '').match(cveRegex) || []
    for (const c of titleMatches) foundCves.add(c.toUpperCase())
    if (row.evidence) {
      try {
        const ev = typeof row.evidence === 'string' ? JSON.parse(row.evidence) : row.evidence
        if (Array.isArray(ev?.knownCves)) {
          for (const k of ev.knownCves) {
            if (k?.id) foundCves.add(String(k.id).toUpperCase().trim())
          }
        }
      } catch { /* ignore */ }
    }

    for (const cveId of foundCves) {
      if (onlyCveIds && !onlyCveIds.has(cveId)) continue
      const intel = cveLookupStmt.get(cveId)
      if (!intel) continue

      const kind = intel.has_kev ? 'kev' : (intel.has_poc ? 'poc' : null)
      if (!kind) continue
      if (alreadySentStmt.get(cveId, row.finding_id, kind)) continue

      candidateMatches.push({
        cveId,
        kind,
        findingId: row.finding_id,
        scanId: row.scan_id,
        target: row.target,
        title: row.title,
        userId: row.user_id,
        client: row.client,
        epssScore: intel.epss_score,
        kevAdded: intel.kev_added,
        sourceCount: intel.source_count || 0,
        topStars: intel.top_stars || 0,
      })
    }
  }

  if (!candidateMatches.length) return { matched: 0, sent: 0 }

  const sendFn = notifier || channelNotifier
  if (typeof sendFn !== 'function') {
    return { matched: candidateMatches.length, sent: 0 }
  }

  await sendFn(candidateMatches)

  const nowIso = new Date().toISOString()
  const txRecord = indexDb.transaction(() => {
    for (const m of candidateMatches) {
      recordSentStmt.run(m.cveId, m.findingId, m.kind, nowIso)
    }
  })
  txRecord()

  return { matched: candidateMatches.length, sent: candidateMatches.length }
}

function scheduleFastTick() {
  if (stopped) return
  if (fastTimer) clearTimeout(fastTimer)
  const intervalMs = Math.max(60000, Number(config.pocindex?.fastIntervalMs || 3600000))
  fastTimer = setTimeout(async () => {
    await syncNow({ full: false })
    scheduleFastTick()
  }, intervalMs)
  fastTimer.unref?.()
}

function scheduleFullTick() {
  if (stopped) return
  if (fullTimer) clearTimeout(fullTimer)
  const intervalMs = Math.max(300000, Number(config.pocindex?.fullIntervalMs || 43200000))
  fullTimer = setTimeout(async () => {
    await syncNow({ full: true })
    scheduleFullTick()
  }, intervalMs)
  fullTimer.unref?.()
}

/**
 * Start background PoC Index scheduler (non-blocking).
 */
export function bootstrap({ notifier = null, triggerInitial = true } = {}) {
  stopped = false
  if (notifier) channelNotifier = notifier
  if (config.pocindex?.enabled === false || config.pocindex?.autoSync === false) {
    return false
  }

  const status = getSyncStatus()
  if (triggerInitial && (!status.dbReady || !status.feeds.length)) {
    const bootTimer = setTimeout(() => {
      if (!stopped) syncNow({ full: true })
    }, 2000)
    bootTimer.unref?.()
  }

  scheduleFastTick()
  scheduleFullTick()
  return true
}

export function stop() {
  stopped = true
  if (fastTimer) { clearTimeout(fastTimer); fastTimer = null }
  if (fullTimer) { clearTimeout(fullTimer); fullTimer = null }
  closePocindexDb()
}

export default {
  bootstrap,
  stop,
  syncNow,
  getSyncStatus,
  setAlertNotifier,
  correlateAndAlertFindings,
  streamJsonArray,
  streamJsonObjectEntries,
}
