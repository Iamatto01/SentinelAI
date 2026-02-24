import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const CVE_DIR = path.resolve(__dirname, '../../cvelistV5-main/cves')

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
 * Returns null if not found or the ID format is invalid.
 */
export async function getCveById(cveId) {
  const filePath = getCvePath(cveId)
  if (!filePath) return null
  try {
    const raw = JSON.parse(await fs.promises.readFile(filePath, 'utf8'))
    return parseCveRecord(raw)
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
