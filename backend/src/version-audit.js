/**
 * VERSION AUDIT — architecture fingerprinting + CVE/CWE correlation.
 *
 * Detects every software version visible on a target (web server, language
 * runtime, framework, CMS, JS library, database hints), then correlates each
 * detected product+version against the NIST NVD to surface known CVEs, and
 * maps the result onto the OWASP Top 10 (2025) category that fits.
 *
 * Detection sources (all passive / read-only):
 *   1. HTTP response headers        (Server, X-Powered-By, X-AspNet-Version, ...)
 *   2. HTML body signatures         (meta generator, asset query strings, comments)
 *   3. whatweb / nmap finding text  (already-collected pipeline evidence)
 *   4. Error-page fingerprints      (SQL errors, stack traces, framework banners)
 *   5. Cookie names                 (MoodleSession, PHPSESSID, JSESSIONID, ...)
 */

import { findVersionVulnerabilities } from './cve.js'

// ── Product signature catalogue ──────────────────────────────────────────────
// Each entry: how to recognise the product, and how to pull its version out.
// `owasp` is the OWASP Top 10 (2025) category a vulnerable version falls under.
export const PRODUCT_SIGNATURES = [
  // ── Web servers ──
  { product: 'Apache HTTP Server', vendor: 'apache', kind: 'web-server', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bApache\/(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'nginx', vendor: 'nginx', kind: 'web-server', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bnginx\/(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Microsoft IIS', vendor: 'microsoft', kind: 'web-server', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bMicrosoft-IIS\/(\d+\.\d+)/i, cwe: 'CWE-1104' },
  { product: 'LiteSpeed', vendor: 'litespeedtech', kind: 'web-server', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bLiteSpeed\b[^\d]{0,10}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'OpenResty', vendor: 'openresty', kind: 'web-server', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bopenresty\/(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Caddy', vendor: 'caddyserver', kind: 'web-server', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bCaddy\/(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Tomcat', vendor: 'apache', kind: 'app-server', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\b(?:Apache[- ])?Tomcat\/?(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Jetty', vendor: 'eclipse', kind: 'app-server', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bJetty[\/ ]\(?(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'WildFly', vendor: 'redhat', kind: 'app-server', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bWildFly\/?(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'JBoss', vendor: 'redhat', kind: 'app-server', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bJBoss[^\d]{0,15}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'WebLogic', vendor: 'oracle', kind: 'app-server', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bWebLogic[^\d]{0,15}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'WebSphere', vendor: 'ibm', kind: 'app-server', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bWebSphere[^\d]{0,15}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },

  // ── Language runtimes ──
  { product: 'PHP', vendor: 'php', kind: 'language', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bPHP\/(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'ASP.NET', vendor: 'microsoft', kind: 'framework', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bASP\.NET[^\d]{0,10}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Node.js', vendor: 'nodejs', kind: 'language', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bNode(?:\.js)?\/(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Express', vendor: 'expressjs', kind: 'framework', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bExpress\/(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Python', vendor: 'python', kind: 'language', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bPython\/(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Ruby', vendor: 'ruby-lang', kind: 'language', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bRuby\/(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Java', vendor: 'oracle', kind: 'language', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\b(?:Java|JRE|JDK)\/?(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Go', vendor: 'golang', kind: 'language', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bGo-http-client\/(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },

  // ── Frameworks / CMS ──
  { product: 'WordPress', vendor: 'wordpress', kind: 'cms', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bWordPress[^\d]{0,20}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Moodle', vendor: 'moodle', kind: 'cms', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bMoodle[^\d]{0,20}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Joomla', vendor: 'joomla', kind: 'cms', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bJoomla!?[^\d]{0,20}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Drupal', vendor: 'drupal', kind: 'cms', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bDrupal[^\d]{0,20}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Django', vendor: 'djangoproject', kind: 'framework', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bDjango[\/ ](\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Flask', vendor: 'palletsprojects', kind: 'framework', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bFlask[\/ ](\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Laravel', vendor: 'laravel', kind: 'framework', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bLaravel[^\d]{0,20}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Symfony', vendor: 'sensiolabs', kind: 'framework', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bSymfony[^\d]{0,20}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Spring Framework', vendor: 'vmware', kind: 'framework', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bSpring(?: Framework)?[\/ ](\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Rails', vendor: 'rubyonrails', kind: 'framework', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bRails[\/ ](\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Next.js', vendor: 'vercel', kind: 'framework', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bNext\.js[^\d]{0,10}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Nuxt', vendor: 'nuxt', kind: 'framework', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bNuxt(?:\.js)?[^\d]{0,10}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Angular', vendor: 'angular', kind: 'framework', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bAngular(?:JS)?[^\d]{0,10}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'React', vendor: 'facebook', kind: 'framework', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bReact(?:DOM)?[^\d]{0,10}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Vue.js', vendor: 'vuejs', kind: 'framework', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bVue(?:\.js)?[^\d]{0,10}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'jQuery', vendor: 'jquery', kind: 'library', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bjQuery[^\d]{0,10}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Bootstrap', vendor: 'getbootstrap', kind: 'library', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bBootstrap[^\d]{0,10}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Struts', vendor: 'apache', kind: 'framework', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bStruts[^\d]{0,15}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'ThinkPHP', vendor: 'thinkphp', kind: 'framework', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bThinkPHP[^\d]{0,15}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'CodeIgniter', vendor: 'codeigniter', kind: 'framework', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bCodeIgniter[^\d]{0,15}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Yii', vendor: 'yiiframework', kind: 'framework', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bYii[^\d]{0,15}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },

  // ── Databases (usually leaked via error pages / banners) ──
  { product: 'MySQL', vendor: 'oracle', kind: 'database', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bMySQL[^\d]{0,15}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'MariaDB', vendor: 'mariadb', kind: 'database', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bMariaDB[^\d]{0,15}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'PostgreSQL', vendor: 'postgresql', kind: 'database', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bPostgreSQL[^\d]{0,15}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Microsoft SQL Server', vendor: 'microsoft', kind: 'database', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\b(?:Microsoft )?SQL Server[^\d]{0,15}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'MongoDB', vendor: 'mongodb', kind: 'database', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bMongoDB[^\d]{0,15}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Redis', vendor: 'redis', kind: 'database', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bRedis[^\d]{0,15}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Elasticsearch', vendor: 'elastic', kind: 'database', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bElasticsearch[^\d]{0,15}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Oracle Database', vendor: 'oracle', kind: 'database', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bOracle Database[^\d]{0,15}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },

  // ── Infrastructure / services ──
  { product: 'OpenSSH', vendor: 'openbsd', kind: 'service', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bOpenSSH[_\s](\d+\.\d+(?:p\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'OpenSSL', vendor: 'openssl', kind: 'library', owasp: 'A04:2025-Cryptographic Failures',
    re: /\bOpenSSL\/(\d+\.\d+(?:\.\d+)?[a-z]?)/i, cwe: 'CWE-327' },
  { product: 'Exim', vendor: 'exim', kind: 'service', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bExim[^\d]{0,10}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Postfix', vendor: 'postfix', kind: 'service', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bPostfix[^\d]{0,10}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'vsftpd', vendor: 'beasts', kind: 'service', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bvsftpd[^\d]{0,10}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'ProFTPD', vendor: 'proftpd', kind: 'service', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bProFTPD[^\d]{0,10}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Samba', vendor: 'samba', kind: 'service', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bSamba[^\d]{0,10}(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'CUPS', vendor: 'openprinting', kind: 'service', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bCUPS[\/ ](\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Docker', vendor: 'docker', kind: 'container', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bDocker[\/ ](\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
  { product: 'Kubernetes', vendor: 'kubernetes', kind: 'container', owasp: 'A03:2025-Software Supply Chain Failures',
    re: /\bKubernetes[\/ ]v?(\d+\.\d+(?:\.\d+)?)/i, cwe: 'CWE-1104' },
]

// ── Cookie → product hints (version usually absent, but product is confirmed) ──
const COOKIE_HINTS = [
  { re: /MoodleSession/i, product: 'Moodle', kind: 'cms' },
  { re: /wordpress_|wp-settings/i, product: 'WordPress', kind: 'cms' },
  { re: /PHPSESSID/i, product: 'PHP', kind: 'language' },
  { re: /JSESSIONID/i, product: 'Java', kind: 'language' },
  { re: /ASP\.NET_SessionId/i, product: 'ASP.NET', kind: 'framework' },
  { re: /laravel_session/i, product: 'Laravel', kind: 'framework' },
  { re: /ci_session/i, product: 'CodeIgniter', kind: 'framework' },
  { re: /django|csrftoken/i, product: 'Django', kind: 'framework' },
  { re: /_rails|_session_id/i, product: 'Rails', kind: 'framework' },
  { re: /connect\.sid/i, product: 'Express', kind: 'framework' },
  { re: /jroute|option=com_joomla|joomla\.js/i, product: 'Joomla', kind: 'cms' },
]

// ── Error-page fingerprints → database / framework confirmation ──
const ERROR_FINGERPRINTS = [
  { re: /You have an error in your SQL syntax|mysql_fetch|MySqlException/i, product: 'MySQL', kind: 'database' },
  { re: /pg_query|PostgreSQL.*ERROR|psql:/i, product: 'PostgreSQL', kind: 'database' },
  { re: /Microsoft OLE DB Provider for SQL Server|SqlException|System\.Data\.SqlClient/i, product: 'Microsoft SQL Server', kind: 'database' },
  { re: /ORA-\d{4,5}|Oracle.*Driver/i, product: 'Oracle Database', kind: 'database' },
  { re: /SQLite3?::|sqlite_|SQLITE_ERROR/i, product: 'SQLite', kind: 'database' },
  { re: /MongoError|MongoServerError|mongodb/i, product: 'MongoDB', kind: 'database' },
  { re: /Redis.*(?:ERR|error)|redis\.exceptions/i, product: 'Redis', kind: 'database' },
  { re: /Whoops|Symfony\\Component|laravel.*exception/i, product: 'Laravel', kind: 'framework' },
  { re: /Traceback \(most recent call last\)|django\.core\.exceptions/i, product: 'Django', kind: 'framework' },
  { re: /at System\.|System\.NullReferenceException|ASP\.NET/i, product: 'ASP.NET', kind: 'framework' },
  { re: /java\.lang\.|org\.springframework|javax\.servlet/i, product: 'Java', kind: 'language' },
  { re: /ActionController|ActiveRecord|Ruby on Rails/i, product: 'Rails', kind: 'framework' },
]

// ── Version extraction from HTML body ────────────────────────────────────────
// `product` may be a function of the match (e.g. meta generator content).
const HTML_PATTERNS = [
  { re: /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i, group: 1, productFromMatch: true },
  { re: /wp-content\/themes\/[^"']+\?ver=([\d.]+)/i, product: 'WordPress', group: 1 },
  { re: /wp-includes\/js\/(?!jquery)[^"']+\?ver=([\d.]+)/i, product: 'WordPress', group: 1 },
  { re: /jquery[.-]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js/i, product: 'jQuery', group: 1 },
  { re: /jquery[^"']*[?&]ver=([\d]+\.[\d]+\.[\d]+)/i, product: 'jQuery', group: 1 },
  { re: /bootstrap[.-]?([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.(?:js|css)/i, product: 'Bootstrap', group: 1 },
  { re: /react(?:-dom)?[.@-]?([\d]+\.[\d]+\.[\d]+)/i, product: 'React', group: 1 },
  { re: /vue[.@-]?([\d]+\.[\d]+\.[\d]+)/i, product: 'Vue.js', group: 1 },
  { re: /angular[.@-]?([\d]+\.[\d]+\.[\d]+)/i, product: 'Angular', group: 1 },
  { re: /moodle[^\d]{0,20}(\d+\.\d+(?:\.\d+)?)/i, product: 'Moodle', group: 1 },
  { re: /Drupal\.settings|drupal\.js\?v=([\d.]+)/i, product: 'Drupal', group: 1 },
  { re: /\/media\/jui\/js\/|joomla/i, product: 'Joomla', group: 1 },
]

/** Split a meta-generator string like "WordPress 5.8.1" into {product, version}. */
function splitGenerator(content) {
  const m = String(content || '').match(/^([A-Za-z][A-Za-z0-9 ._+-]{1,40}?)[\s\/v]+(\d+\.\d+(?:\.\d+)?)/)
  if (!m) return null
  return { product: m[1].trim(), version: m[2] }
}

/**
 * Extract every (product, version) pair from a blob of text.
 * @param {string} text  concatenated headers + body + tool output
 * @param {string} source label describing where the text came from
 * @returns {Array<{product,version,kind,owasp,cwe,source,matched}>}
 */
export function extractVersions(text, source = 'unknown') {
  const blob = String(text || '')
  if (!blob) return []
  const found = new Map()

  for (const sig of PRODUCT_SIGNATURES) {
    const m = blob.match(sig.re)
    if (!m) continue
    const version = (m[1] || '').trim()
    if (!version || !/\d/.test(version)) continue
    const key = `${sig.product}@${version}`.toLowerCase()
    if (found.has(key)) continue
    found.set(key, {
      product: sig.product,
      vendor: sig.vendor,
      version,
      kind: sig.kind,
      owasp: sig.owasp,
      cwe: sig.cwe,
      source,
      matched: m[0].slice(0, 120),
    })
  }

  // HTML-specific patterns (may add products the generic regexes missed)
  for (const p of HTML_PATTERNS) {
    const m = blob.match(p.re)
    if (!m) continue
    let product = p.product
    let version = (m[p.group] || '').trim()
    if (p.productFromMatch) {
      const split = splitGenerator(m[1])
      if (!split) continue
      product = split.product
      version = split.version
    }
    if (!product || !version || !/\d/.test(version)) continue
    const key = `${product}@${version}`.toLowerCase()
    if (found.has(key)) continue
    const sig = PRODUCT_SIGNATURES.find(s => s.product.toLowerCase() === product.toLowerCase())
    found.set(key, {
      product,
      vendor: sig?.vendor || null,
      version,
      kind: sig?.kind || 'unknown',
      owasp: sig?.owasp || 'A03:2025-Software Supply Chain Failures',
      cwe: sig?.cwe || 'CWE-1104',
      source,
      matched: m[0].slice(0, 120),
    })
  }

  return [...found.values()]
}

/**
 * Detect products WITHOUT a version (version obscured by WAF/CDN).
 * These still matter: the product is confirmed present, so the report can
 * say "version unverified — manual check required".
 */
export function extractProductsWithoutVersion(text, source = 'unknown') {
  const blob = String(text || '')
  const out = []
  const seen = new Set()
  for (const hint of COOKIE_HINTS) {
    if (!hint.re.test(blob)) continue
    if (seen.has(hint.product)) continue
    seen.add(hint.product)
    out.push({ product: hint.product, kind: hint.kind, source, reason: 'cookie-name' })
  }
  for (const fp of ERROR_FINGERPRINTS) {
    if (!fp.re.test(blob)) continue
    if (seen.has(fp.product)) continue
    seen.add(fp.product)
    out.push({ product: fp.product, kind: fp.kind, source, reason: 'error-fingerprint' })
  }
  return out
}

/**
 * Correlate a detected product+version against NVD.
 * Returns the enriched record with CVEs sorted by CVSS descending.
 */
export async function correlateVersion({ product, version, log } = {}) {
  try {
    const nvd = await findVersionVulnerabilities(product, version)
    if (!nvd || nvd.error) return { product, version, cves: [], error: nvd?.error || 'lookup failed' }
    const cves = (nvd.results || [])
      .filter(r => r.cvss?.score != null)
      .sort((a, b) => (b.cvss?.score || 0) - (a.cvss?.score || 0))
    const critical = cves.filter(c => (c.cvss?.score || 0) >= 9.0).length
    const high = cves.filter(c => (c.cvss?.score || 0) >= 7.0 && (c.cvss?.score || 0) < 9.0).length
    const medium = cves.filter(c => (c.cvss?.score || 0) >= 4.0 && (c.cvss?.score || 0) < 7.0).length
    if (log) log(`🔍 ${product} ${version}: ${cves.length} CVE(s) — ${critical} critical, ${high} high, ${medium} medium`)
    return { product, version, cves, critical, high, medium, total: cves.length }
  } catch (e) {
    return { product, version, cves: [], error: e.message }
  }
}

/**
 * Derive a finding severity from the CVE distribution.
 * A version with a critical CVE is critical; with only high CVEs is high; etc.
 */
export function severityFromCves({ critical = 0, high = 0, medium = 0, total = 0 } = {}) {
  if (critical > 0) return 'critical'
  if (high > 0) return 'high'
  if (medium > 0) return 'medium'
  if (total > 0) return 'low'
  return 'info'
}

/**
 * Build a human-readable finding for a detected version with known CVEs.
 */
export function buildVersionFinding(detected, correlation) {
  const { product, version, kind, owasp, cwe, source, matched } = detected
  const { cves = [], critical = 0, high = 0, medium = 0, total = 0 } = correlation || {}
  const severity = severityFromCves({ critical, high, medium, total })
  const top = cves[0]
  const cveList = cves.slice(0, 10).map(c => ({
    id: c.id,
    score: c.cvss?.score,
    severity: c.cvss?.severity || c.severity,
    description: (c.description || '').slice(0, 300),
    cwe: (c.weaknesses || []).filter(w => /^CWE-/.test(w)).slice(0, 3),
    references: (c.references || []).slice(0, 5),
  }))

  const sevBreakdown = [
    critical ? `${critical} critical` : '',
    high ? `${high} high` : '',
    medium ? `${medium} medium` : '',
  ].filter(Boolean).join(', ')

  return {
    title: `${product} ${version} — ${total} known CVE${total === 1 ? '' : 's'}${sevBreakdown ? ` (${sevBreakdown})` : ''}`,
    severity,
    cweId: cwe || 'CWE-1104',
    cveId: top?.id || null,
    owaspCategory: owasp || 'A03:2025-Software Supply Chain Failures',
    description:
      `The target exposes ${product} ${version} (${kind}) via ${source}. ` +
      `NIST NVD lists ${total} published CVE${total === 1 ? '' : 's'} matching this product and version` +
      `${sevBreakdown ? `, including ${sevBreakdown}` : ''}. ` +
      (top
        ? `The highest-scoring is ${top.id} (CVSS ${top.cvss?.score ?? 'n/a'}): ${(top.description || '').slice(0, 240)} `
        : '') +
      `Running a version with published CVEs means any attacker with a vulnerability scanner can identify and attempt these exploits without any custom research.`,
    remediation:
      `Upgrade ${product} from ${version} to the latest stable release. ` +
      `If an immediate upgrade is not possible, apply the vendor security patches for the CVEs listed, ` +
      `and add WAF rules that block the known exploit patterns. ` +
      `Suppress the version banner (e.g. server_tokens off in nginx, ServerTokens Prod in Apache) so future scans cannot fingerprint the exact build.`,
    module: 'version-audit',
    evidence: {
      product,
      version,
      kind,
      detectedFrom: matched,
      detectionSource: source,
      totalCves: total,
      criticalCount: critical,
      highCount: high,
      mediumCount: medium,
      knownCves: cveList,
      nvdQuery: `${product} ${version}`,
      references: cveList.flatMap(c => c.references || []),
    },
  }
}

/**
 * Build a finding for a product detected WITHOUT a version.
 * Lower severity — the risk is unquantified, but the exposure is real.
 */
export function buildUnversionedFinding(detected) {
  const { product, kind, source, reason } = detected
  return {
    title: `${product} detected — version obscured, CVE exposure unverified`,
    severity: 'low',
    cweId: 'CWE-1104',
    owaspCategory: 'A03:2025-Software Supply Chain Failures',
    description:
      `${product} (${kind}) was identified on the target via ${reason === 'cookie-name' ? 'its session cookie name' : 'an error-page fingerprint'}, ` +
      `but the exact version is not exposed. This is usually caused by a WAF/CDN stripping version banners — good hygiene, ` +
      `but it means the CVE exposure of this component cannot be measured remotely. ` +
      `Confirm the installed version from the server itself and cross-check it against the vendor security advisories.`,
    remediation:
      `Record the installed ${product} version in your asset inventory and subscribe to the vendor's security advisory feed. ` +
      `Keep the version banner suppressed (this is already the case) and patch on the vendor's release cadence.`,
    module: 'version-audit',
    evidence: { product, kind, detectionSource: source, reason, versionUnverified: true },
  }
}

export default {
  PRODUCT_SIGNATURES,
  extractVersions,
  extractProductsWithoutVersion,
  correlateVersion,
  severityFromCves,
  buildVersionFinding,
  buildUnversionedFinding,
}
