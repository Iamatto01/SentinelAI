// Scan coverage model.
//
// A scan can only find what its toolchain can reach. When a tool such as
// `sqlmap` or `dalfox` is absent from the scanning host, the corresponding
// vulnerability class is never exercised -- yet the report still prints a
// confident "ELEVATED RISK" posture, which reads as "we tested everything and
// found this much". That is a false statement about scope, not a false
// severity, and it is the more dangerous of the two.
//
// This module turns a tool-availability map into an explicit coverage
// descriptor so the pipeline can persist it and the report can say, on page 1,
// exactly which classes were never tested.
//
// No imports on purpose: `report.js` rehydrates a stored descriptor and must
// not drag in the native tool runner to do it.

// Each class lists the tools that can exercise it (`anyOf` semantics -- one
// present tool makes the class testable). `critical: true` marks classes whose
// absence invalidates the headline risk posture rather than merely narrowing
// it: a report that never attempted injection or XSS cannot be summarised as
// "no emergency critical issues detected".
export const COVERAGE_CLASSES = [
  {
    id: 'injection',
    label: 'SQL / NoSQL / command injection',
    anyOf: ['sqlmap'],
    critical: true,
    passiveNote: 'passive payload reflection only',
  },
  {
    id: 'xss',
    label: 'Cross-site scripting (reflected / stored)',
    anyOf: ['dalfox'],
    critical: true,
    passiveNote: 'passive payload reflection only',
  },
  {
    id: 'cve',
    label: 'Known-CVE matching',
    anyOf: ['nuclei'],
    critical: false,
    passiveNote: 'banner version comparison only',
  },
  {
    id: 'crawling',
    label: 'Endpoint / route discovery',
    anyOf: ['katana', 'gau'],
    critical: false,
    passiveNote: 'static link extraction only',
  },
  {
    id: 'content_discovery',
    label: 'Directory / file brute force',
    anyOf: ['ffuf', 'feroxbuster', 'gobuster', 'dirsearch'],
    critical: false,
    passiveNote: 'dictionary seeding only',
  },
  {
    id: 'parameter_discovery',
    label: 'Hidden parameter discovery',
    anyOf: ['arjun'],
    critical: false,
    passiveNote: 'crawled parameter extraction only',
  },
  {
    id: 'tls',
    label: 'TLS / cipher configuration',
    anyOf: ['sslscan'],
    critical: false,
    passiveNote: 'certificate metadata only',
  },
  {
    id: 'fingerprinting',
    label: 'Technology fingerprinting',
    anyOf: ['whatweb', 'httpx'],
    critical: false,
    passiveNote: 'response header analysis only',
  },
]

export const COVERAGE_CLASS_IDS = COVERAGE_CLASSES.map((c) => c.id)

const isTruthy = (v) => v === true || v === 'true' || v === 1

/**
 * Normalise whatever `nativeToolsStatus()` returned into `Set`-like lookups.
 * Accepts `{ sqlmap: true }` and tolerates a persisted array of names.
 */
function availableSet(toolStatus) {
  if (Array.isArray(toolStatus)) return new Set(toolStatus.map(String))
  const set = new Set()
  if (toolStatus && typeof toolStatus === 'object') {
    for (const [k, v] of Object.entries(toolStatus)) if (isTruthy(v)) set.add(k)
  }
  return set
}

/**
 * Build a coverage descriptor.
 *
 * @param {object|string[]} toolStatus  from `nativeToolsStatus()`
 * @param {object} [opts]
 * @param {string[]} [opts.modules]     explicitly requested tools; empty = full toolchain
 * @returns {{
 *   available: string[], missing: string[], degraded: boolean,
 *   criticalGaps: string[], gaps: string[], covered: string[],
 *   untestedClasses: object[], summary: string, passiveOnly: boolean
 * }}
 */
export function buildCoverage(toolStatus, opts = {}) {
  const have = availableSet(toolStatus)
  const modules = Array.isArray(opts.modules) ? opts.modules.filter(Boolean) : []
  const explicitSelection = modules.length > 0

  const gaps = []
  const covered = []
  const untestedClasses = []

  for (const cls of COVERAGE_CLASSES) {
    // When the operator picked specific modules, a class is only "in scope" if
    // one of its tools was actually requested. Otherwise the full toolchain was
    // intended and every class is in scope.
    const inScope = !explicitSelection || cls.anyOf.some((t) => modules.includes(t))
    if (!inScope) continue

    const present = cls.anyOf.filter((t) => have.has(t))
    if (present.length) {
      covered.push(cls.id)
    } else {
      gaps.push(cls.id)
      untestedClasses.push({ id: cls.id, label: cls.label, missingTools: cls.anyOf.slice(), note: cls.passiveNote, critical: Boolean(cls.critical) })
    }
  }

  const criticalGaps = gaps.filter((id) => {
    const cls = COVERAGE_CLASSES.find((c) => c.id === id)
    return Boolean(cls && cls.critical)
  })

  // Every tool in the registry that this host lacks -- informational, used by
  // the "N/25 tools available" log line and the API payload for the UI warning.
  const missing = []
  if (toolStatus && !Array.isArray(toolStatus) && typeof toolStatus === 'object') {
    for (const [k, v] of Object.entries(toolStatus)) if (!isTruthy(v)) missing.push(k)
  }

  // `degraded` drives the page-1 suppression: a critical class untested means
  // the posture headline is not a supportable claim.
  const degraded = criticalGaps.length > 0

  return {
    available: [...have],
    missing,
    degraded,
    criticalGaps,
    gaps,
    covered,
    untestedClasses,
    passiveOnly: covered.length === 0,
    summary: summarise(untestedClasses, degraded),
  }
}

function summarise(untestedClasses, degraded) {
  if (!untestedClasses.length) return 'Full toolchain available - all in-scope vulnerability classes were exercised.'
  const parts = untestedClasses.map((c) => {
    const tool = c.missingTools[0]
    const tested = c.note ? ` Coverage is ${c.note}.` : ''
    return `${c.label}: NOT TESTED (${tool} unavailable).${tested}`
  })
  const lead = degraded
    ? 'INCOMPLETE ASSESSMENT - one or more critical vulnerability classes were never exercised.'
    : 'Reduced coverage - some vulnerability classes were not exercised.'
  return `${lead} ${parts.join(' ')}`
}

/**
 * Rehydrate coverage from a persisted blob. Accepts either a stored descriptor
 * (returned as-is when it already carries a class list) or a stored
 * tool-availability map, so an old scan row can still yield a usable answer.
 */
export function rehydrateCoverage(stored, fallback = null) {  if (!stored) return fallback
  let blob = stored
  if (typeof stored === 'string') {
    try { blob = JSON.parse(stored) } catch { return fallback }
  }
  if (!blob || typeof blob !== 'object') return fallback
  if (Array.isArray(blob.untestedClasses) && Array.isArray(blob.gaps)) return blob
  // Old shape: a bare `{ tool: boolean }` availability map.
  const tools = blob.tools && typeof blob.tools === 'object' ? blob.tools : blob
  const keys = Object.keys(tools)
  if (!keys.length) return fallback
  if (keys.every((k) => typeof tools[k] === 'boolean')) return buildCoverage(tools, { modules: blob.modules })
  return fallback
}

/**
 * Pull the coverage descriptor out of a scan row's `blackbox_meta` JSON blob.
 *
 * `blackbox_meta` is a multi-writer column (the tool inventory, the subdomain /
 * URL pool, and now the coverage descriptor), so the descriptor lives at
 * `blob.coverage` rather than at the root. Degrades to `null` on anything
 * unparseable so a report can always render.
 *
 * @param {string|object|null} stored  raw `scans.blackbox_meta` value
 * @returns {object|null} coverage descriptor, or null when the row predates it
 */
export function coverageFromMeta(stored) {
  if (!stored) return null
  let blob = stored
  if (typeof stored === 'string') {
    try { blob = JSON.parse(stored) } catch { return null }
  }
  if (!blob || typeof blob !== 'object') return null
  return rehydrateCoverage(blob.coverage, null)
}
