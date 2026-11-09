import * as db from './db.js'

/**
 * CVE lookup via the NIST NVD API v2, cached in SQLite (cve_cache) for 24h.
 * Replaces SentinelAI's local cvelistV5 git-clone (huge, not portable).
 * No API key required (rate-limited to ~5 req/30s without one).
 */

const NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
const TTL_MS = 24 * 60 * 60 * 1000
// Negative results expire fast: an empty NVD answer is the one cache entry most
// likely to become wrong (CPE map change, NVD hiccup, fixed query builder).
const NEGATIVE_TTL_MS = 15 * 60 * 1000

/**
 * Normalise Moodle date-based internal build stamps (e.g. 2022112819.04)
 * into semantic release numbers (e.g. 4.1.19 or 4.1) so NIST NVD CPE lookup matches.
 */
export function normalizeMoodleVersion(verStr) {
  if (!verStr) return verStr
  const s = String(verStr).trim()
  const m = s.match(/^(\d{8})(\d{2})?(?:\.(\d+))?/)
  if (m) {
    const datePart = m[1]
    const point = m[2] !== undefined ? parseInt(m[2], 10) : null
    const map = {
      '20241007': '4.5',
      '20240422': '4.4',
      '20231009': '4.3',
      '20230424': '4.2',
      '20221128': '4.1',
      '20220419': '4.0',
      '20210517': '3.11',
      '20201109': '3.10',
      '20200615': '3.9',
      '20191118': '3.8',
      '20190520': '3.7',
      '20181203': '3.6',
      '20180517': '3.5',
    }
    if (map[datePart]) {
      return point !== null ? `${map[datePart]}.${point}` : map[datePart]
    }
  }
  return s
}

/**
 * Version "coverage": a truncated fingerprint (`1.18`) matches a CPE range
 * either as that exact build or as the whole branch (`1.18.0`, `1.18.7`).
 * NVD ranges are usually written for the full three-component release
 * (`>= 1.18.0`), so treating `1.18` as an exact string silently discarded
 * every real advisory for that branch.
 */
export function coversVersion(observed, bound) {
  const lean = (v) => String(v == null ? '' : v).toLowerCase().replace(/^v/, '').trim()
  const a = lean(observed)
  const b = lean(bound)
  if (!a || !b) return false
  if (compareVersions(a, b) === 0) return true
  const aParts = a.split('.').filter(Boolean)
  if (aParts.length >= 3) return false
  return b.startsWith(`${a}.`)
}

/**
 * Order two dotted version strings. Non-numeric suffixes are compared as
 * strings so `1.18.0-rc1` still orders before `1.18.0`, and a truncated
 * version (`1.18`) compares equal to its zero-padded form (`1.18.0`).
 */
export function compareVersions(a, b) {
  const norm = (v) => String(v == null ? '' : v)
    .toLowerCase()
    .replace(/^v/, '')
    .split(/[^0-9a-z.]+/)
    .filter(Boolean)
    .join('.')
  const split = (v) => norm(v).split('.').filter(Boolean)
  const pa = split(a)
  const pb = split(b)

  const len = Math.max(pa.length, pb.length)
  for (let i = 0; i < len; i++) {
    const x = pa[i]
    const y = pb[i]
    // Past the common prefix: a trailing zero group is padding (`1.18` == `1.18.0`),
    // a trailing numeric group is a later build, and a trailing non-numeric group
    // is a pre-release tag (`rc1`, `beta`) that sorts BEFORE the plain release.
    if (x === undefined || y === undefined) {
      const extra = x === undefined ? y : x
      const longerIsA = x !== undefined
      if (/^\d+$/.test(extra)) {
        if (Number(extra) === 0) continue
        return longerIsA ? 1 : -1
      }
      return longerIsA ? -1 : 1
    }
    const xn = /^\d+$/.test(x)
    const yn = /^\d+$/.test(y)
    if (xn && yn) {
      const dx = Number(x)
      const dy = Number(y)
      if (dx !== dy) return dx > dy ? 1 : -1
    } else if (x !== y) {
      return x > y ? 1 : -1
    }
  }
  return 0
}

/**
 * Does one NVD cpeMatch entry cover the version we observed?
 *
 * A CVE's `configurations` carry the machine-readable applicability window
 * (`versionStartIncluding` / `versionEndExcluding` / exact CPE version). The
 * previous client ignored them completely and trusted the keyword hit, which is
 * how a report ends up citing advisories for a release that was never installed.
 */
function cpeMatchApplies(match, version) {
  if (!match || match.vulnerable === false) return false
  const criteria = String(match.criteria || '')
  const parts = criteria.split(':')
  const cpeVersion = parts[5] || '*'
  const v = String(version || '')
  const startIncl = match.versionStartIncluding
  const startExcl = match.versionStartExcluding
  const endIncl = match.versionEndIncluding
  const endExcl = match.versionEndExcluding
  const hasRange = Boolean(startIncl || startExcl || endIncl || endExcl)

  if (!hasRange && (cpeVersion === '*' || cpeVersion === '-')) return false
  if (!hasRange) return coversVersion(v, cpeVersion)
  // Lower bounds: a truncated branch (`1.18`) is not "below" a bound that lives
  // inside it (`1.18.0`) — it covers it. Only reject when it truly sits under.
  if (startIncl && compareVersions(v, startIncl) < 0 && !coversVersion(v, startIncl)) return false
  if (startExcl && compareVersions(v, startExcl) <= 0 && !coversVersion(v, startExcl)) return false
  // Upper bounds: reject only when the whole branch sits above the window.
  if (endIncl && compareVersions(v, endIncl) > 0) return false
  if (endExcl && compareVersions(v, endExcl) >= 0) return false
  return true
}

/**
 * Walk a CVE's configurations looking for a vulnerable cpeMatch that covers the
 * observed version for the product we actually fingerprinted. Matches for
 * unrelated products in the same advisory (operating systems, bundled libraries)
 * are ignored.
 */
function findApplicability(configurations, vendor, cpeProduct, version) {
  const wantVendor = String(vendor || '').toLowerCase()
  const wantProduct = String(cpeProduct || '').toLowerCase()
  const ranges = []
  let productMatched = false
  for (const config of Array.isArray(configurations) ? configurations : []) {
    for (const node of config?.nodes || []) {
      for (const match of node?.cpeMatch || []) {
        const parts = String(match?.criteria || '').split(':')
        if (parts[3]?.toLowerCase() !== wantVendor) continue
        if (parts[4]?.toLowerCase() !== wantProduct) continue
        productMatched = true
        if (cpeMatchApplies(match, version)) {
          ranges.push({
            criteria: match.criteria,
            startIncluding: match.versionStartIncluding || null,
            startExcluding: match.versionStartExcluding || null,
            endIncluding: match.versionEndIncluding || null,
            endExcluding: match.versionEndExcluding || null,
          })
        }
      }
    }
  }
  return { ranges, productMatched }
}

function parseNvd(cve, applicability = null) {
  const metrics = cve.metrics || {}
  const m =
    metrics.cvssMetricV40?.[0]?.cvssData ||
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
    cvss: m ? {
      score: m.baseScore,
      severity: m.baseSeverity || null,
      vector: m.vectorString,
      version: m.version || (metrics.cvssMetricV40?.length ? '4.0' : null),
    } : null,
    severity: m?.baseSeverity || null,
    weaknesses,
    references: references.slice(0, 12),
    // `null` means applicability was not checked (keyword mode).
    // An array means it was checked; length > 0 proves the version is in range.
    applicableRanges: applicability,
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

/**
 * NVD CPE vendor/product pairs for the products this scanner fingerprints.
 *
 * Two problems this solves:
 *  1. NVD's keywordSearch with a version term returns almost nothing, so a
 *     perfectly vulnerable server reported "0 CVEs" and the report implied it
 *     was clean.
 *  2. Product display names ("Apache HTTP Server", "Microsoft IIS") are not CPE
 *     names ("apache:http_server", "microsoft:internet_information_services").
 *
 * `vendors` may hold several entries: nginx moved to `f5` but older advisories
 * sit under `nginx`, and both must be searched.
 */
const CPE_MAP = {
  'apache http server': { vendors: ['apache'], product: 'http_server' },
  'nginx': { vendors: ['f5', 'nginx'], product: 'nginx' },
  'microsoft iis': { vendors: ['microsoft'], product: 'internet_information_services' },
  'litespeed': { vendors: ['litespeedtech'], product: 'litespeed_web_server' },
  'openresty': { vendors: ['openresty'], product: 'openresty' },
  'caddy': { vendors: ['caddyserver'], product: 'caddy' },
  'tomcat': { vendors: ['apache'], product: 'tomcat' },
  'jetty': { vendors: ['eclipse'], product: 'jetty' },
  'wildfly': { vendors: ['redhat'], product: 'wildfly' },
  'jboss': { vendors: ['redhat'], product: 'jboss_enterprise_application_platform' },
  'weblogic': { vendors: ['oracle'], product: 'weblogic_server' },
  'websphere': { vendors: ['ibm'], product: 'websphere_application_server' },
  'php': { vendors: ['php'], product: 'php' },
  'asp.net': { vendors: ['microsoft'], product: 'asp.net_core' },
  'node.js': { vendors: ['nodejs'], product: 'node.js' },
  'express': { vendors: ['expressjs'], product: 'express' },
  'python': { vendors: ['python'], product: 'python' },
  'ruby': { vendors: ['ruby-lang'], product: 'ruby' },
  'java': { vendors: ['oracle'], product: 'jre' },
  'go': { vendors: ['golang'], product: 'go' },
  'wordpress': { vendors: ['wordpress'], product: 'wordpress' },
  'moodle': { vendors: ['moodle'], product: 'moodle' },
  'joomla': { vendors: ['joomla'], product: 'joomla!' },
  'drupal': { vendors: ['drupal'], product: 'drupal' },
  'django': { vendors: ['djangoproject'], product: 'django' },
  'flask': { vendors: ['palletsprojects'], product: 'flask' },
  'laravel': { vendors: ['laravel'], product: 'laravel' },
  'symfony': { vendors: ['sensiolabs'], product: 'symfony' },
  'spring framework': { vendors: ['vmware'], product: 'spring_framework' },
  'rails': { vendors: ['rubyonrails'], product: 'rails' },
  'next.js': { vendors: ['vercel'], product: 'next.js' },
  'nuxt': { vendors: ['nuxtjs'], product: 'nuxt.js' },
  'angular': { vendors: ['google'], product: 'angular' },
  'angularjs': { vendors: ['angularjs'], product: 'angular.js' },
  'react': { vendors: ['facebook'], product: 'react' },
  'vue.js': { vendors: ['vuejs'], product: 'vue.js' },
  'jquery': { vendors: ['jquery'], product: 'jquery' },
  'bootstrap': { vendors: ['getbootstrap'], product: 'bootstrap' },
  'struts': { vendors: ['apache'], product: 'struts' },
  'thinkphp': { vendors: ['thinkphp'], product: 'thinkphp' },
  'codeigniter': { vendors: ['codeigniter'], product: 'codeigniter' },
  'yii': { vendors: ['yiiframework'], product: 'yii' },
  'mysql': { vendors: ['oracle'], product: 'mysql' },
  'mariadb': { vendors: ['mariadb'], product: 'mariadb' },
  'postgresql': { vendors: ['postgresql'], product: 'postgresql' },
  'microsoft sql server': { vendors: ['microsoft'], product: 'sql_server' },
  'mongodb': { vendors: ['mongodb'], product: 'mongodb' },
  'redis': { vendors: ['redis'], product: 'redis' },
  'elasticsearch': { vendors: ['elastic'], product: 'elasticsearch' },
  'oracle database': { vendors: ['oracle'], product: 'database_server' },
  'openssh': { vendors: ['openbsd'], product: 'openssh' },
  'openssl': { vendors: ['openssl'], product: 'openssl' },
  'exim': { vendors: ['exim'], product: 'exim' },
  'postfix': { vendors: ['postfix'], product: 'postfix' },
  'vsftpd': { vendors: ['vsftpd_project'], product: 'vsftpd' },
  'proftpd': { vendors: ['proftpd'], product: 'proftpd' },
  'samba': { vendors: ['samba'], product: 'samba' },
  'cups': { vendors: ['openprinting'], product: 'cups' },
  'docker': { vendors: ['docker'], product: 'docker' },
  'kubernetes': { vendors: ['kubernetes'], product: 'kubernetes' },
}

function cpeTargets(product) {
  const key = String(product || '').toLowerCase().trim()
  const mapped = CPE_MAP[key]
  if (mapped) return mapped.vendors.map(vendor => ({ vendor, product: mapped.product }))
  const slug = key.replace(/[^a-z0-9.]+/g, '_').replace(/^_+|_+$/g, '')
  return slug ? [{ vendor: null, product: slug }] : []
}

/** Search NVD for an observed component/version. These are CVE candidates;
 * CPE applicability and installed version must be confirmed before reporting. */
export async function findVersionVulnerabilities(product, version) {
  const name = String(product || '').trim()
  let release = String(version || '').trim()
  if (name.toLowerCase() === 'moodle') {
    release = normalizeMoodleVersion(release)
  }
  if (!name || !release || name.length > 100 || release.length > 80) return { error: 'product and version are required' }
  const key = `cpev:${name.toLowerCase()}:${release.toLowerCase()}`
  const cached = db.get(`SELECT data, fetched_at FROM cve_cache WHERE id = ?`, key)
  if (cached && Date.now() - new Date(cached.fetched_at).getTime() < TTL_MS) {
    try {
      const parsed = JSON.parse(cached.data)
      // A negative answer is the weakest possible evidence: an empty NVD response
      // can mean "no such CVE" or "CPE mapping was wrong that day". Serving one
      // for a full TTL makes a corrected CPE map look permanently broken, so
      // negatives are retried on a short window and positives keep the full TTL.
      const isNegative = !Array.isArray(parsed.results) || parsed.results.length === 0
      const age = Date.now() - new Date(cached.fetched_at).getTime()
      if (!isNegative || age < NEGATIVE_TTL_MS) return { ...parsed, cached: true }
    } catch { /* refresh */ }
  }

  const targets = cpeTargets(name)
  const applicable = []
  const outOfRange = []
  const unconfirmed = []
  const reasons = []

  for (const target of targets) {
    try {
      const params = new URLSearchParams({ resultsPerPage: '2000' })
      params.set(
        'virtualMatchString',
        target.vendor
          ? `cpe:2.3:a:${target.vendor}:${target.product}`
          : `cpe:2.3:*:*:${target.product}`,
      )
      const ctrl = new AbortController()
      const t = setTimeout(() => ctrl.abort(), 20000)
      const res = await fetch(`${NVD}?${params}`, {
        headers: { 'User-Agent': 'fyp2-pentest-platform' },
        signal: ctrl.signal,
      })
      clearTimeout(t)
      if (!res.ok) { reasons.push(`NVD HTTP ${res.status} for ${target.vendor || '*'}${target.vendor ? ':' : ':*:'}${target.product}`); continue }
      const json = await res.json()
      for (const entry of json.vulnerabilities || []) {
        const cve = entry.cve
        if (!cve?.id) continue
        const appInfo = target.vendor
          ? findApplicability(cve.configurations, target.vendor, target.product, release)
          : null
        if (appInfo && appInfo.ranges.length > 0) {
          applicable.push(parseNvd(cve, appInfo.ranges))
        } else if (appInfo && appInfo.productMatched && appInfo.ranges.length === 0) {
          outOfRange.push(parseNvd(cve, []))
        } else {
          unconfirmed.push(parseNvd(cve, null))
        }
      }
    } catch (error) {
      reasons.push(error.name === 'AbortError' ? 'NVD request timed out' : error.message)
    }
  }

  const dedupe = (list) => {
    const seen = new Set()
    return list.filter(c => (seen.has(c.id) ? false : (seen.add(c.id), true)))
  }
  const scored = dedupe(applicable).sort((a, b) => (b.cvss?.score || 0) - (a.cvss?.score || 0))
  const excluded = dedupe(outOfRange)
    .filter(c => !scored.some(s => s.id === c.id))
    .sort((a, b) => (b.cvss?.score || 0) - (a.cvss?.score || 0))
  const possibly = dedupe(unconfirmed)
    .filter(c => !scored.some(s => s.id === c.id) && !excluded.some(e => e.id === c.id))
    .sort((a, b) => (b.cvss?.score || 0) - (a.cvss?.score || 0))
    .slice(0, 10)

  if (!targets.length) return { error: 'product could not be mapped to a CPE name' }
  if (!scored.length && !possibly.length && !excluded.length && reasons.length === targets.length) {
    return { error: reasons.join('; ') || 'NVD lookup failed' }
  }

  const totalOutOfRange = excluded.length
  const outOfRangeSample = excluded.slice(0, 3).map(c => ({ id: c.id, score: c.cvss?.score ?? null }))

  const output = {
    product: name,
    version: release,
    applicability: 'cpe-version-range-checked',
    cpeTargets: targets.map(t => `${t.vendor || '*'}:${t.product}`),
    results: scored,
    // Advisories that name the product but whose range does not include this
    // build. Reported separately so the reader can see the negative.
    outOfRangeCount: totalOutOfRange,
    outOfRangeSample,
    reasons: reasons.length ? reasons : undefined,
  }
  db.run(
    `INSERT INTO cve_cache (id, data, fetched_at) VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET data = excluded.data, fetched_at = excluded.fetched_at`,
    key, JSON.stringify(output), new Date().toISOString(),
  )
  return output
}

export default { getCve, findVersionVulnerabilities, compareVersions }
