import fs from 'node:fs'
import path from 'node:path'
import zlib from 'node:zlib'
import { fileURLToPath } from 'node:url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const CVE_DIR = path.resolve(__dirname, '../../cvelistV5-main/cves')
const INDEX_FILE_GZ = path.resolve(__dirname, 'data/cve-product-index.json.gz')
const INDEX_FILE = path.resolve(__dirname, 'data/cve-product-index.json')

/* ── In-memory CVE product index ─────────────────────────────────────── */

let productIndex = null // product → CVEEntry[]
const cveCache = new Map() // cveId → parsed record
const CACHE_MAX = 2000

/**
 * Load the pre-built product index into memory.
 * Call once at server startup.
 */
export async function loadCveProductIndex() {
  try {
    let raw
    // Try gzip first, then plain JSON
    if (fs.existsSync(INDEX_FILE_GZ)) {
      const compressed = await fs.promises.readFile(INDEX_FILE_GZ)
      raw = zlib.gunzipSync(compressed).toString('utf8')
    } else if (fs.existsSync(INDEX_FILE)) {
      raw = await fs.promises.readFile(INDEX_FILE, 'utf8')
    } else {
      throw new Error('No index file found')
    }
    productIndex = JSON.parse(raw)
    const products = Object.keys(productIndex).length
    const entries = Object.values(productIndex).reduce((s, a) => s + a.length, 0)
    console.log(`[cve] Product index loaded: ${products} products, ${entries} CVE entries`)
    return true
  } catch (err) {
    console.warn(`[cve] Product index not found. Run: node backend/src/buildCveIndex.js`)
    productIndex = {}
    return false
  }
}

/**
 * Check if the product index is loaded and has data.
 */
export function isIndexLoaded() {
  return productIndex !== null && Object.keys(productIndex).length > 0
}

/* ── Version comparison ──────────────────────────────────────────────── */

/**
 * Parse a version string into numeric segments for comparison.
 * "1.23.4" → [1, 23, 4]
 */
function parseVersionSegments(ver) {
  if (!ver) return null
  const segments = ver.replace(/^v/i, '').split(/[.\-+]/).map((s) => {
    const n = parseInt(s, 10)
    return isNaN(n) ? 0 : n
  })
  return segments.length > 0 ? segments : null
}

/**
 * Compare two version arrays.
 * Returns <0 if a<b, 0 if a===b, >0 if a>b.
 */
function compareVersions(a, b) {
  if (!a || !b) return 0
  const len = Math.max(a.length, b.length)
  for (let i = 0; i < len; i++) {
    const sa = a[i] || 0
    const sb = b[i] || 0
    if (sa !== sb) return sa - sb
  }
  return 0
}

/**
 * Check if a detected version matches a CVE version constraint.
 * Returns true if the detected version falls within the vulnerable range.
 */
export function matchVersion(detectedVersion, constraint) {
  if (!detectedVersion || !constraint) return false

  const detected = parseVersionSegments(detectedVersion)
  if (!detected) return false

  // If the constraint has a specific affected version with no range, do exact prefix match
  if (constraint.version && !constraint.lessThan && !constraint.lessThanOrEqual) {
    if (constraint.version === '0' || constraint.version === 'unspecified') return true
    const cv = parseVersionSegments(constraint.version)
    if (!cv) return false
    return compareVersions(detected, cv) === 0
  }

  // Range: version <= detected < lessThan
  if (constraint.version && constraint.lessThan) {
    const from = parseVersionSegments(constraint.version)
    const to = parseVersionSegments(constraint.lessThan)
    if (!from || !to) return false
    return compareVersions(detected, from) >= 0 && compareVersions(detected, to) < 0
  }

  // Range: version <= detected <= lessThanOrEqual
  if (constraint.version && constraint.lessThanOrEqual) {
    const from = parseVersionSegments(constraint.version)
    const to = parseVersionSegments(constraint.lessThanOrEqual)
    if (!from || !to) return false
    return compareVersions(detected, from) >= 0 && compareVersions(detected, to) <= 0
  }

  // Only lessThan (no lower bound)
  if (constraint.lessThan) {
    const to = parseVersionSegments(constraint.lessThan)
    if (!to) return false
    return compareVersions(detected, to) < 0
  }

  // Only lessThanOrEqual (no lower bound)
  if (constraint.lessThanOrEqual) {
    const to = parseVersionSegments(constraint.lessThanOrEqual)
    if (!to) return false
    return compareVersions(detected, to) <= 0
  }

  return false
}

/* ── Product-based CVE search ────────────────────────────────────────── */

/**
 * Normalise a product name for index lookup.
 */
function normaliseForLookup(name) {
  return (name || '')
    .toLowerCase()
    .replace(/[_\-]/g, ' ')
    .replace(/\.js$/i, '')
    .replace(/\s+/g, ' ')
    .trim()
}

/**
 * Search the CVE product index for a given technology name.
 * Optionally filter by detected version.
 *
 * @param {string} productName - Technology name (e.g. "nginx", "WordPress")
 * @param {string|null} detectedVersion - Detected version or null
 * @param {{ limit?: number }} options
 * @returns {Array} Array of matching CVE entries
 */
export function searchByProduct(productName, detectedVersion = null, { limit = 15 } = {}) {
  if (!productIndex) return []

  const normalised = normaliseForLookup(productName)
  if (!normalised) return []

  // Try exact match first, then partial matches
  let entries = productIndex[normalised] || []

  // If no exact match, try partial key matching
  if (entries.length === 0) {
    for (const key of Object.keys(productIndex)) {
      if (key.includes(normalised) || normalised.includes(key)) {
        entries = entries.concat(productIndex[key])
      }
    }
  }

  if (entries.length === 0) return []

  // If we have a version, filter to entries where the version is vulnerable
  if (detectedVersion) {
    const versionMatches = entries.filter((e) => {
      if (!e.versions || e.versions.length === 0) return false
      return e.versions.some((v) => matchVersion(detectedVersion, v))
    })
    // If version filtering found results, use them; otherwise return top entries
    if (versionMatches.length > 0) {
      return versionMatches.slice(0, limit)
    }
  }

  // No version or no version matches: return top entries by CVSS (already sorted)
  return entries.slice(0, limit)
}

/* ── Single CVE record lookup ────────────────────────────────────────── */

/**
 * Resolve the file path for a given CVE ID.
 * e.g. CVE-2024-0001 → .../cves/2024/0xxx/CVE-2024-0001.json
 */
export function getCvePath(cveId) {
  const match = cveId.match(/^CVE-(\d{4})-(\d+)$/i)
  if (!match) return null
  const year = match[1]
  const num = parseInt(match[2], 10)
  const folder = Math.floor(num / 1000) + 'xxx'
  return path.join(CVE_DIR, year, folder, `${cveId.toUpperCase()}.json`)
}

/**
 * Parse a raw CVE JSON record into a clean summary object.
 */
function parseCveRecord(raw) {
  const meta = raw.cveMetadata || {}
  const cna = raw.containers?.cna || {}

  const desc =
    cna.descriptions?.find((d) => d.lang === 'en')?.value || '(No description)'

  const cvssV3 =
    cna.metrics?.[0]?.cvssV3_1 || cna.metrics?.[0]?.cvssV3_0 || null

  const problemTypes = (cna.problemTypes || []).flatMap(
    (p) => p.descriptions?.map((d) => d.description) || [],
  )

  const affected = (cna.affected || []).map((a) => ({
    vendor: a.vendor,
    product: a.product,
    versions: a.versions,
  }))

  return {
    cveId: meta.cveId,
    state: meta.state,
    datePublished: meta.datePublished,
    dateUpdated: meta.dateUpdated,
    description: desc,
    cvss: cvssV3
      ? {
          score: cvssV3.baseScore,
          severity: cvssV3.baseSeverity,
          vector: cvssV3.vectorString,
          attackVector: cvssV3.attackVector,
          attackComplexity: cvssV3.attackComplexity,
        }
      : null,
    problemTypes,
    affected,
    references: (cna.references || []).map((r) => r.url).filter(Boolean),
  }
}

/**
 * Fetch a single CVE record by ID from the local CVEListV5 database.
 * Uses an in-memory cache for performance.
 */
export async function getCveById(cveId) {
  // Check cache
  if (cveCache.has(cveId)) return cveCache.get(cveId)

  const filePath = getCvePath(cveId)
  if (!filePath) return null
  try {
    const raw = JSON.parse(await fs.promises.readFile(filePath, 'utf8'))
    const parsed = parseCveRecord(raw)
    // Store in cache (evict oldest if full)
    if (cveCache.size >= CACHE_MAX) {
      const firstKey = cveCache.keys().next().value
      cveCache.delete(firstKey)
    }
    cveCache.set(cveId, parsed)
    return parsed
  } catch {
    return null
  }
}

/**
 * Search CVEs by keyword across the local CVEListV5 database.
 * Scans description text in recent years first for performance.
 * @param {string} keyword - Search term
 * @param {{ years?: string[], limit?: number }} options
 */
export async function searchCve(keyword, { years, limit = 20 } = {}) {
  const searchYears = years || ['2025', '2024', '2023']
  const results = []
  const kw = keyword.toLowerCase()

  for (const year of searchYears) {
    if (results.length >= limit) break
    const yearDir = path.join(CVE_DIR, year)

    let subFolders
    try {
      subFolders = await fs.promises.readdir(yearDir)
    } catch {
      continue
    }

    for (const sub of subFolders) {
      if (results.length >= limit) break
      const subDir = path.join(yearDir, sub)

      let files
      try {
        files = await fs.promises.readdir(subDir)
      } catch {
        continue
      }

      for (const file of files) {
        if (results.length >= limit) break
        if (!file.endsWith('.json')) continue
        try {
          const raw = JSON.parse(
            await fs.promises.readFile(path.join(subDir, file), 'utf8'),
          )
          const cna = raw.containers?.cna || {}
          const desc =
            cna.descriptions?.find((d) => d.lang === 'en')?.value || ''
          if (desc.toLowerCase().includes(kw)) {
            results.push(parseCveRecord(raw))
          }
        } catch {
          // skip malformed files
        }
      }
    }
  }

  return results
}
