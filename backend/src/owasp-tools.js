/**
 * OWASP Top 10 (2025) → Tool Mapping
 *
 * Maps each OWASP category to the tools/methods that detect vulnerabilities
 * in that category, for both blackbox (DAST) and whitebox (SAST) scans.
 *
 * Used by:
 *   - Frontend NewScanModal: to show tools under each OWASP tick section
 *   - Backend pipeline: to filter which tools to run based on selected categories
 *   - ScanDetail: to show which tools cover each category
 */

import { OWASP } from './owasp.js'

// ── BLACKBOX (DAST) TOOLS PER OWASP CATEGORY ──────────────────────────
// Each tool maps to one or more OWASP categories. If a category is unticked,
// tools that ONLY cover that category are skipped.
const BLACKBOX_OWASP_TOOLS = {
  'A01': [
    { tool: 'nmap',        desc: 'NSE scripts: smb-enum-shares, rdp-vuln, path traversal' },
    { tool: 'ffuf',        desc: 'Forced browsing — discovers hidden paths & IDOR endpoints' },
    { tool: 'gobuster',    desc: 'Directory/path brute force — exposes restricted areas' },
    { tool: 'katana',      desc: 'Crawler — discovers parameterized routes (IDOR surface)' },
    { tool: 'arjun',       desc: 'Hidden parameter discovery — access control bypass' },
  ],
  'A02': [
    { tool: 'nikto',       desc: 'Security headers, debug pages, misconfig checks' },
    { tool: 'nuclei',      desc: 'Misconfiguration templates (CORS, debug, exposure)' },
    { tool: 'whatweb',     desc: 'Server header / tech stack exposure detection' },
    { tool: 'wafw00f',     desc: 'WAF fingerprint & security posture' },
    { tool: 'httpx',       desc: 'HTTP probe — banner, response headers' },
    { tool: 'ffuf',        desc: 'Directory listing, .htaccess exposure' },
  ],
  'A03': [
    { tool: 'nuclei',      desc: 'CVE templates for vulnerable components & libraries' },
    { tool: 'nikto',       desc: 'Outdated software / server version detection' },
    { tool: 'whatweb',     desc: 'Technology fingerprint — identifies dependency versions' },
    { tool: 'nmap',        desc: 'Service version detection — flags known-vulnerable versions' },
  ],
  'A04': [
    { tool: 'nmap',        desc: 'NSE: ssl-cert, ssl-enum-ciphers, weak protocols' },
    { tool: 'nuclei',      desc: 'TLS/SSL misconfig & weak cipher templates' },
    { tool: 'whatweb',     desc: 'Detects HTTP vs HTTPS, cert validity' },
    { tool: 'wafw00f',     desc: 'TLS inspection' },
  ],
  'A05': [
    { tool: 'sqlmap',      desc: 'SQL injection — automated union-based to time-blind' },
    { tool: 'dalfox',     desc: 'XSS — reflected, stored, DOM-based injection' },
    { tool: 'arjun',       desc: 'Hidden parameter discovery for injection vectors' },
    { tool: 'nuclei',      desc: 'Injection templates (SSTI, SSRF, code injection)' },
    { tool: 'nikto',       desc: 'CGI & injection-prone endpoint detection' },
    { tool: 'katana',      desc: 'Crawl parameterized URLs for injection testing' },
    { tool: 'ffuf',        desc: 'Fuzz parameters for error-based injection' },
  ],
  'A06': [
    { tool: 'nikto',       desc: 'Default credentials & insecure defaults' },
    { tool: 'nuclei',      desc: 'Weak design patterns (missing rate-limit, etc.)' },
    { tool: 'nmap',        desc: 'Default-creds NSE scripts across services' },
  ],
  'A07': [
    { tool: 'nikto',       desc: 'Authentication misconfig & session cookie flags' },
    { tool: 'nuclei',      desc: 'Auth bypass, JWT, session templates' },
    { tool: 'nmap',        desc: 'Default credentials NSE on SSH/FTP/HTTP' },
    { tool: 'wpscan',     desc: 'WordPress auth & user enumeration (WP only)' },
  ],
  'A08': [
    { tool: 'nuclei',      desc: 'Deserialization & integrity check templates' },
    { tool: 'nikto',       desc: 'Unsafe file inclusion / deserialization endpoints' },
    { tool: 'nmap',        desc: 'Service-level integrity probing' },
  ],
  'A09': [
    { tool: 'nikto',       desc: 'Missing security headers (X-Frame, CSP, HSTS)' },
    { tool: 'nuclei',      desc: 'Information disclosure & logging failure templates' },
    { tool: 'whatweb',     desc: 'Error page & verbose output detection' },
  ],
  'A10': [
    { tool: 'nmap',        desc: 'NSE: http-errors, service crash, DoS probes' },
    { tool: 'nuclei',      desc: 'Error-handling & crash disclosure templates' },
    { tool: 'nikto',       desc: 'Verbose error & stack trace exposure' },
  ],
}

// ── WHITEBOX (SAST) METHODS PER OWASP CATEGORY ────────────────────────
// Whitebox uses pattern scanner (regex rules) + AI audit passes.
const WHITEBOX_OWASP_METHODS = {
  'A01': [
    { tool: 'Pattern Scanner', desc: 'Path traversal, IDOR, open redirect, CSRF detection' },
    { tool: 'AI Security Agent', desc: 'Broken access control & business logic analysis' },
  ],
  'A02': [
    { tool: 'Pattern Scanner', desc: 'CORS misconfig, debug mode, XXE, file upload detection' },
    { tool: 'AI Security Agent', desc: 'Security headers & misconfiguration review' },
  ],
  'A03': [
    { tool: 'Pattern Scanner', desc: 'Dependency version & vulnerable component detection' },
    { tool: 'AI Security Agent', desc: 'Outdated library & supply chain risk analysis' },
  ],
  'A04': [
    { tool: 'Pattern Scanner', desc: 'MD5/SHA1, weak crypto, hardcoded keys, cleartext detection' },
    { tool: 'AI Security Agent', desc: 'Cryptographic failure & TLS misconfig review' },
  ],
  'A05': [
    { tool: 'Pattern Scanner', desc: 'SQLi, XSS, SSTI, command injection, eval/exec detection' },
    { tool: 'AI Security Agent', desc: 'Injection flaw & user-input-to-sink tracing' },
  ],
  'A06': [
    { tool: 'Pattern Scanner', desc: 'Missing rate limit, weak password policy detection' },
    { tool: 'AI Security Agent', desc: 'Insecure design & business logic review' },
  ],
  'A07': [
    { tool: 'Pattern Scanner', desc: 'Hardcoded credentials, JWT misuse, weak auth detection' },
    { tool: 'AI Security Agent', desc: 'Authentication & session management review' },
  ],
  'A08': [
    { tool: 'Pattern Scanner', desc: 'Unsafe deserialization, pickle, yaml.load detection' },
    { tool: 'AI Security Agent', desc: 'Data integrity & untrusted deserialization review' },
  ],
  'A09': [
    { tool: 'Pattern Scanner', desc: 'console.log, missing logging, log injection detection' },
    { tool: 'AI Security Agent', desc: 'Security logging & monitoring gap review' },
  ],
  'A10': [
    { tool: 'Pattern Scanner', desc: 'Swallowed errors, empty catch, unhandled promise detection' },
    { tool: 'AI Security Agent', desc: 'Exception handling & error management review' },
  ],
}

// ── REVERSE MAP: tool → OWASP categories it covers ─────────────────────
// Used to determine which tools to skip when categories are unticked.
const BLACKBOX_TOOL_CATEGORIES = {}
for (const [cat, tools] of Object.entries(BLACKBOX_OWASP_TOOLS)) {
  for (const { tool } of tools) {
    if (!BLACKBOX_TOOL_CATEGORIES[tool]) BLACKBOX_TOOL_CATEGORIES[tool] = []
    if (!BLACKBOX_TOOL_CATEGORIES[tool].includes(cat)) {
      BLACKBOX_TOOL_CATEGORIES[tool].push(cat)
    }
  }
}

/**
 * Given a list of selected OWASP categories, return the tools that should run.
 * A tool runs if at least one of its categories is selected.
 */
export function toolsForCategories(categories, mode = 'blackbox') {
  const map = mode === 'whitebox' ? WHITEBOX_OWASP_METHODS : BLACKBOX_OWASP_TOOLS
  const result = []
  for (const cat of categories) {
    if (map[cat]) {
      for (const t of map[cat]) {
        if (!result.find(r => r.tool === t.tool)) result.push(t)
      }
    }
  }
  return result
}

/**
 * Given selected categories (array of 'A01'...'A10','OTH'), return the
 * blackbox module names to pass to pipeline.runBlackbox.
 */
export function blackboxModulesForCategories(categories) {
  const mods = new Set()
  for (const cat of categories) {
    if (BLACKBOX_OWASP_TOOLS[cat]) {
      for (const { tool } of BLACKBOX_OWASP_TOOLS[cat]) {
        mods.add(tool)
      }
    }
  }
  return [...mods]
}

/**
 * Given selected categories, return the whitebox AI pass tags to run.
 * Maps categories to the 3 existing AI passes + pattern scanner.
 */
export function whiteboxPassesForCategories(categories) {
  const passes = []

  // Pattern scanner covers all categories — always run if any selected
  if (categories.length) passes.push('pattern')

  // Injection pass → A05
  if (categories.includes('A05')) passes.push('injection')

  // Auth-secrets pass → A04, A07
  if (categories.includes('A04') || categories.includes('A07')) passes.push('auth-secrets')

  // Logic-config pass → A01, A02, A03, A06, A08, A09, A10
  if (categories.some(c => ['A01','A02','A03','A06','A08','A09','A10'].includes(c))) {
    passes.push('logic-config')
  }

  return passes
}

/**
 * Get full OWASP category metadata with associated tools.
 */
export function getOwaspToolMapList() {
  return Object.entries(OWASP).map(([code, meta]) => ({
    code,
    id: meta.id,
    name: meta.name,
    tools: BLACKBOX_OWASP_TOOLS[code] || [],
    blackboxTools: BLACKBOX_OWASP_TOOLS[code] || [],
    methods: WHITEBOX_OWASP_METHODS[code] || [],
    whiteboxMethods: WHITEBOX_OWASP_METHODS[code] || [],
  }))
}

export {
  BLACKBOX_OWASP_TOOLS,
  WHITEBOX_OWASP_METHODS,
  BLACKBOX_TOOL_CATEGORIES,
}
