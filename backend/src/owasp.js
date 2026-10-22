/**
 * OWASP Top 10 (2025) mapper — keyword + CWE driven, compact.
 * Maps every finding into one of the 10 OWASP 2025 categories, or an
 * "Others" bucket for anything clearly outside the Top 10.
 */
export const OWASP = {
  'A01': { id: 'A01:2025', name: 'Broken Access Control' },
  'A02': { id: 'A02:2025', name: 'Security Misconfiguration' },
  'A03': { id: 'A03:2025', name: 'Software Supply Chain Failures' },
  'A04': { id: 'A04:2025', name: 'Cryptographic Failures' },
  'A05': { id: 'A05:2025', name: 'Injection' },
  'A06': { id: 'A06:2025', name: 'Insecure Design' },
  'A07': { id: 'A07:2025', name: 'Authentication Failures' },
  'A08': { id: 'A08:2025', name: 'Software or Data Integrity Failures' },
  'A09': { id: 'A09:2025', name: 'Security Logging and Alerting Failures' },
  'A10': { id: 'A10:2025', name: 'Mishandling of Exceptional Conditions' },
  'OTH': { id: 'OTH', name: 'Others' },
}

// CWE → OWASP 2025 category mapping
const CWE_MAP = {
  // A01 Broken Access Control
  'CWE-22': 'A01', 'CWE-23': 'A01', 'CWE-352': 'A01', 'CWE-639': 'A01', 'CWE-284': 'A01',
  'CWE-862': 'A01', 'CWE-863': 'A01', 'CWE-601': 'A01', 'CWE-425': 'A01', 'CWE-285': 'A01',
  'CWE-269': 'A01',
  // A02 Security Misconfiguration
  'CWE-16': 'A02', 'CWE-260': 'A02', 'CWE-489': 'A02', 'CWE-942': 'A02',
  'CWE-1004': 'A02', 'CWE-2': 'A02', 'CWE-5': 'A02', 'CWE-200': 'A02', 'CWE-209': 'A02',
  'CWE-611': 'A02', 'CWE-614': 'A02', 'CWE-693': 'A02', 'CWE-698': 'A02', 'CWE-1327': 'A02',
  // A03 Software Supply Chain Failures
  'CWE-1104': 'A03', 'CWE-829': 'A03', 'CWE-1357': 'A03', 'CWE-494': 'A03', 'CWE-710': 'A03',
  // A04 Cryptographic Failures
  'CWE-327': 'A04', 'CWE-328': 'A04', 'CWE-319': 'A04', 'CWE-312': 'A04', 'CWE-330': 'A04',
  'CWE-338': 'A04', 'CWE-326': 'A04', 'CWE-311': 'A04', 'CWE-347': 'A04', 'CWE-295': 'A04',
  'CWE-321': 'A04', 'CWE-322': 'A04', 'CWE-323': 'A04', 'CWE-329': 'A04', 'CWE-331': 'A04',
  'CWE-798': 'A04',
  // A05 Injection
  'CWE-89': 'A05', 'CWE-78': 'A05', 'CWE-79': 'A05', 'CWE-77': 'A05', 'CWE-90': 'A05',
  'CWE-94': 'A05', 'CWE-917': 'A05', 'CWE-643': 'A05', 'CWE-93': 'A05', 'CWE-95': 'A05',
  'CWE-98': 'A05', 'CWE-943': 'A05', 'CWE-1336': 'A05', 'CWE-434': 'A05', 'CWE-20': 'A05',
  'CWE-502': 'A05', 'CWE-1321': 'A05',
  // A06 Insecure Design
  'CWE-937': 'A06', 'CWE-1188': 'A06', 'CWE-747': 'A06', 'CWE-799': 'A06', 'CWE-307': 'A06',
  'CWE-770': 'A06', 'CWE-522': 'A06', 'CWE-602': 'A06', 'CWE-521': 'A06',
  // A07 Authentication Failures
  'CWE-287': 'A07', 'CWE-306': 'A07', 'CWE-384': 'A07', 'CWE-294': 'A07',
  'CWE-640': 'A07', 'CWE-620': 'A07', 'CWE-308': 'A07', 'CWE-613': 'A07',
  // A08 Software or Data Integrity Failures
  'CWE-502': 'A08', 'CWE-829': 'A08', 'CWE-494': 'A08', 'CWE-345': 'A08', 'CWE-353': 'A08',
  'CWE-565': 'A08',
  // A09 Security Logging and Alerting Failures
  'CWE-532': 'A09', 'CWE-778': 'A09', 'CWE-117': 'A09', 'CWE-223': 'A09',
  // A10 Mishandling of Exceptional Conditions
  'CWE-209': 'A10', 'CWE-248': 'A10', 'CWE-703': 'A10', 'CWE-600': 'A10', 'CWE-390': 'A10',
  'CWE-391': 'A10', 'CWE-755': 'A10', 'CWE-754': 'A10', 'CWE-369': 'A10', 'CWE-617': 'A10',
  // Others
  'CWE-918': 'OTH', // SSRF moved out of Top 10 2025
}

const KEYWORD_MAP = [
  // A05 Injection
  [/ssrf|server.side request forgery/i, 'OTH'],
  [/sql injection|sqli|command injection|code injection|ssti|template injection|ldap|xpath|nosql|\binjection\b/i, 'A05'],
  [/xss|cross-site scripting|innerhtml|outerhtml|dangerouslysetinnerhtml|v-html/i, 'A05'],
  [/eval\(|exec\(|shell_exec|child_process|os\.system|popen|spawn/i, 'A05'],
  // A01 Broken Access Control
  [/idor|broken access|access control|csrf|path traversal|directory traversal|forced browsing|open redirect|privilege escalation|mass assignment|missing @useguards|missing @roles/i, 'A01'],
  // A07 Authentication Failures
  [/jwt|authentication|session fixation|credential|password|brute force|default cred|login bypass|mfa|session timeout/i, 'A07'],
  // A04 Cryptographic Failures
  [/weak (cipher|hash|crypto)|cleartext|insecure transport|tls|ssl|certificate|cryptograph|md5|sha1|math\.random|hardcoded.*(secret|key)|private key/i, 'A04'],
  // A08 Software or Data Integrity Failures
  [/deserialization|pickle|yaml\.load|prototype pollution|unserialize|integrity/i, 'A08'],
  // A03 Software Supply Chain Failures
  [/outdated|known vulnerab|cve-|vulnerable component|dependency|package\.json|npm audit|composer/i, 'A03'],
  // A02 Security Misconfiguration
  [/misconfig|cors|security header|header|directory listing|debug|default config|information disclosure|verbose error|xxe|xml external entity|file upload|server.*banner/i, 'A02'],
  // A09 Security Logging and Alerting Failures
  [/logging|monitoring|logs?\.(info|debug|error|warn)|console\.(log|error|warn)/i, 'A09'],
  // A06 Insecure Design
  [/business logic|insecure design|missing control|missing rate limit|rate limit|missing input validation|weak default/i, 'A06'],
  // A10 Mishandling of Exceptional Conditions
  [/exception|error handling|unhandled|panic|catch.*empty|swallowed error|mishandl/i, 'A10'],
]

export function mapOwasp(finding = {}) {
  if (finding.cweId) {
    const cwe = String(finding.cweId).toUpperCase().replace(/^(CWE-)?/, 'CWE-')
    if (CWE_MAP[cwe]) return CWE_MAP[cwe]
  }
  const text = `${finding.title || ''} ${finding.description || ''}`
  for (const [re, cat] of KEYWORD_MAP) if (re.test(text)) return cat
  return 'OTH'
}

export function enrichWithOwasp(finding) {
  // Normalize any incoming OWASP category (legacy 2021 codes or bare "A0X"
  // prefixes) to the current OWASP Top 10 (2025) category.
  const code = finding.owaspCategory
    ? normalizeOwasp(finding.owaspCategory)
    : mapOwasp(finding)
  const meta = OWASP[code] || OWASP['OTH']
  return { ...finding, owaspCategory: `${meta.id}-${meta.name}`, owasp: meta }
}

// Map legacy OWASP 2021 category codes to the current 2025 codes.
const LEGACY_2021_TO_2025 = {
  'A01': 'A01', // Broken Access Control
  'A02': 'A04', // Cryptographic Failures
  'A03': 'A05', // Injection
  'A04': 'A06', // Insecure Design
  'A05': 'A02', // Security Misconfiguration
  'A06': 'A03', // Vulnerable & Outdated Components → Software Supply Chain Failures
  'A07': 'A07', // Authentication Failures
  'A08': 'A08', // Software & Data Integrity Failures
  'A09': 'A09', // Security Logging & Monitoring Failures
  'A10': 'OTH', // SSRF → Others (no longer in Top 10 2025)
}

/**
 * Convert a stored OWASP label to the 2025 code.
 * Labels already tagged with the 2025 edition are returned as-is — only
 * pre-2025 labels (or bare codes) go through the legacy remap.
 */
export function normalizeOwasp(label) {
  const raw = String(label || '')
  const m = raw.match(/^A0?(\d{1,2})/i)
  if (!m) return 'OTH'
  const code = `A${String(m[1]).padStart(2, '0')}`
  const year = raw.match(/A\d{1,2}\s*:\s*(\d{4})/i)
  if (year && Number(year[1]) >= 2025) return OWASP[code] ? code : 'OTH'
  return LEGACY_2021_TO_2025[code] || 'OTH'
}

export default { OWASP, mapOwasp, enrichWithOwasp }
