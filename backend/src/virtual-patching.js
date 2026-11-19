const SAFE_PATH = /^\/[A-Za-z0-9._~!$&'()*+,;=:@%\/-]{1,240}$/

function findingPath(finding = {}) {
  const evidence = typeof finding.evidence === 'string'
    ? (() => { try { return JSON.parse(finding.evidence) } catch { return {} } })()
    : (finding.evidence || {})
  const candidates = [
    evidence.path,
    evidence.endpoint,
    evidence.url,
    ...(Array.isArray(finding.locations) ? finding.locations : []),
  ]
  for (const candidate of candidates) {
    try {
      const value = String(candidate || '').trim()
      if (value.startsWith('http')) {
        const path = new URL(value).pathname
        if (SAFE_PATH.test(path)) return path
      } else if (SAFE_PATH.test(value.split('?')[0])) {
        return value.split('?')[0]
      }
    } catch { /* ignore malformed evidence */ }
  }
  return '/'
}

function family(finding = {}) {
  const text = `${finding.module || ''} ${finding.title || ''} ${finding.description || ''}`.toLowerCase()
  if (/sql|sqli|database/.test(text)) return 'sql'
  if (/path traversal|directory traversal|local file|lfi/.test(text)) return 'traversal'
  if (/xss|cross.site scripting|script injection/.test(text)) return 'xss'
  if (/command injection|os command/.test(text)) return 'command'
  if (/ssrf|server.side request/.test(text)) return 'ssrf'
  return 'generic'
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

export function generateWafRules(finding = {}) {
  const path = findingPath(finding)
  const escapedPath = escapeRegex(path)
  const kind = family(finding)
  const expression = kind === 'sql'
    ? `http.request.uri.path eq "${path}" and (http.request.uri.query matches "(?i)(union|select|sleep|benchmark|or[+]?[0-9])")`
    : kind === 'traversal'
      ? `http.request.uri.path eq "${path}" and http.request.uri.query matches "(?i)(\\.\\./|%2e%2e|%252e%252e)"`
      : kind === 'xss'
        ? `http.request.uri.path eq "${path}" and http.request.uri.query matches "(?i)(%3c|<)(script|svg|img)"`
        : `http.request.uri.path eq "${path}"`

  const modsec = kind === 'sql'
    ? `SecRule REQUEST_URI "@streq ${path}" "id:100${Math.abs(hash(finding.title || path))},phase:2,deny,status:403,log,msg:'SentinelAI SQL injection virtual patch'"`
    : kind === 'traversal'
      ? `SecRule REQUEST_URI "@streq ${path}" "id:100${Math.abs(hash(finding.title || path))},phase:2,deny,status:403,log,msg:'SentinelAI traversal virtual patch'"`
      : `SecRule REQUEST_URI "@streq ${path}" "id:100${Math.abs(hash(finding.title || path))},phase:2,deny,status:403,log,msg:'SentinelAI finding virtual patch'"`

  return {
    generatedAt: new Date().toISOString(),
    findingId: finding.id || null,
    scope: { path, family: kind },
    warning: 'Review and tune this rule in staging before deployment. This is a compensating control, not a code fix.',
    cloudflare: { action: 'block', expression },
    modSecurity: modsec,
    nginx: `location ~* ^${escapedPath}$ { return 403; }`,
    awsWaf: {
      name: `sentinelai-${kind}-${Math.abs(hash(path))}`,
      statement: { byteMatch: { fieldToMatch: 'uriPath', positionalConstraint: 'EXACTLY', searchString: path } },
      action: 'BLOCK',
    },
  }
}

function hash(value) {
  let result = 0
  for (const char of String(value)) result = ((result << 5) - result + char.charCodeAt(0)) | 0
  return result || 1
}

export default { generateWafRules }
