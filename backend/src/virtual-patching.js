const SAFE_PATH = /^\/[A-Za-z0-9._~!$&'()*+,;=:@%\/-]{1,240}$/

const RULE_PROFILES = {
  sql: {
    label: 'SQL injection',
    cfCondition: '(http.request.uri.query matches "(?i)(union(\\\\s+all)?\\\\s+select|select\\\\b.+\\\\bfrom|sleep\\\\(|benchmark\\\\(|or[+]?[0-9]|\'--)" or http.request.body.raw matches "(?i)(union(\\\\s+all)?\\\\s+select|sleep\\\\(|benchmark\\\\()")',
    modsecVars: 'ARGS|ARGS_NAMES|REQUEST_BODY',
    modsecRx: '(?i)(union(?:\\s+all)?\\s+select|select\\b.+\\bfrom|sleep\\(|benchmark\\(|or[+]?[0-9]|\\x27--)',
    nginxChecks: [
      'if ($args ~* "(union(\\\\s+all)?\\\\s+select|select\\\\b.+\\\\bfrom|sleep\\\\(|benchmark\\\\(|or[+]?[0-9]|\'--)") { return 403; }',
    ],
    awsRegex: '(union(\\s+all)?\\s+select|select\\b.+\\bfrom|sleep\\(|benchmark\\(|or[+]?[0-9]|\'--)',
  },
  traversal: {
    label: 'traversal',
    cfCondition: '(http.request.uri.query matches "(?i)(\\\\.\\\\./|\\\\.\\\\.\\\\\\\\|%2e%2e|%252e%252e|/etc/passwd|/etc/shadow)" or http.request.uri.path matches "(?i)(\\\\.\\\\./|%2e%2e|%252e%252e)")',
    modsecVars: 'REQUEST_URI|ARGS|ARGS_NAMES|REQUEST_BODY',
    modsecRx: '(?i)(\\.\\./|\\.\\.\\\\|%2e%2e|%252e%252e|/etc/passwd|/etc/shadow|win\\.ini)',
    nginxChecks: [
      'if ($request_uri ~* "(\\.\\./|\\.\\.\\\\|%2e%2e|%252e%252e|/etc/passwd|/etc/shadow|win\\.ini)") { return 403; }',
    ],
    awsRegex: '(\\.\\./|\\.\\.\\\\|%2e%2e|%252e%252e|/etc/passwd|/etc/shadow|win\\.ini)',
  },
  xss: {
    label: 'XSS',
    cfCondition: '(http.request.uri.query matches "(?i)(%3c|<)(script|svg|img|iframe)|javascript:|onerror=" or http.request.body.raw matches "(?i)(%3c|<)(script|svg|img|iframe)|javascript:|onerror=")',
    modsecVars: 'ARGS|ARGS_NAMES|REQUEST_BODY',
    modsecRx: '(?i)(?:%3c|<)(?:script|svg|img|iframe)|javascript:|onerror\\s*=',
    nginxChecks: [
      'if ($args ~* "((%3c|<)(script|svg|img|iframe)|javascript:|onerror=)") { return 403; }',
    ],
    awsRegex: '((%3c|<)(script|svg|img|iframe)|javascript:|onerror=)',
  },
  command: {
    label: 'command injection',
    cfCondition: '(http.request.uri.query matches "(?i)(;|\\\\|\\\\||&&|\\\\$\\\\(|%3b|%7c|%26%26|\\\\b(whoami|uname|/bin/sh|/bin/bash)\\\\b)" or http.request.body.raw matches "(?i)(;|\\\\|\\\\||&&|\\\\$\\\\(|\\\\b(whoami|uname|/bin/sh|/bin/bash)\\\\b)")',
    modsecVars: 'ARGS|ARGS_NAMES|REQUEST_BODY',
    modsecRx: '(?i)(?:;|\\|\\||&&|\\$\\(|%3b|%7c|%26%26|\\b(?:whoami|uname|/bin/sh|/bin/bash)\\b)',
    nginxChecks: [
      'if ($args ~* "(;|\\|\\||&&|\\$\\(|%3b|%7c|%26%26|\\b(whoami|uname|/bin/sh|/bin/bash)\\b)") { return 403; }',
    ],
    awsRegex: '(;|\\|\\||&&|\\$\\(|%3b|%7c|%26%26|\\b(whoami|uname|/bin/sh|/bin/bash)\\b)',
  },
  ssrf: {
    label: 'SSRF',
    cfCondition: '(http.request.uri.query matches "(?i)(169\\\\.254\\\\.169\\\\.254|metadata\\\\.google\\\\.internal|127\\\\.0\\\\.0\\\\.1|0\\\\.0\\\\.0\\\\.0|localhost|\\\\[::1\\\\]|file://|gopher://)" or http.request.body.raw matches "(?i)(169\\\\.254\\\\.169\\\\.254|metadata\\\\.google\\\\.internal|127\\\\.0\\\\.0\\\\.1|localhost|file://|gopher://)" or any(http.request.headers["x-forwarded-host"][*] matches "(?i)(169\\\\.254\\\\.169\\\\.254|127\\\\.0\\\\.0\\\\.1|localhost)"))',
    modsecVars: 'ARGS|ARGS_NAMES|REQUEST_BODY|REQUEST_HEADERS',
    modsecRx: '(?i)(?:169\\.254\\.169\\.254|metadata\\.google\\.internal|127\\.0\\.0\\.1|0\\.0\\.0\\.0|localhost|\\[::1\\]|file://|gopher://)',
    nginxChecks: [
      'if ($args ~* "(169\\.254\\.169\\.254|metadata\\.google\\.internal|127\\.0\\.0\\.1|0\\.0\\.0\\.0|localhost|file://|gopher://)") { return 403; }',
      'if ($http_x_forwarded_host ~* "(169\\.254\\.169\\.254|metadata\\.google\\.internal|127\\.0\\.0\\.1|localhost)") { return 403; }',
    ],
    awsRegex: '(169\\.254\\.169\\.254|metadata\\.google\\.internal|127\\.0\\.0\\.1|0\\.0\\.0\\.0|localhost|\\[::1\\]|file://|gopher://)',
    awsHeader: 'x-forwarded-host',
  },
  generic: {
    label: 'finding',
    cfCondition: '(http.request.uri.query matches "(?i)(\\\\.\\\\./|%2e%2e|<script|%3cscript|union\\\\s+select|169\\\\.254\\\\.169\\\\.254|\\\\$\\\\{jndi:|;\\\\s*(cat|id|whoami))" or http.request.body.raw matches "(?i)(\\\\.\\\\./|<script|union\\\\s+select|169\\\\.254\\\\.169\\\\.254|\\\\$\\\\{jndi:)" or any(http.request.headers["user-agent"][*] matches "(?i)(sqlmap|nikto|nessus|\\\\$\\\\{jndi:)"))',
    modsecVars: 'ARGS|ARGS_NAMES|REQUEST_BODY|REQUEST_HEADERS',
    modsecRx: '(?i)(?:\\.\\./|%2e%2e|<script|%3cscript|union\\s+select|169\\.254\\.169\\.254|\\$\\{jndi:|sqlmap|nikto)',
    nginxChecks: [
      'if ($args ~* "(\\.\\./|%2e%2e|<script|%3cscript|union\\s+select|169\\.254\\.169\\.254|\\$\\{jndi:|;\\s*(cat|id|whoami))") { return 403; }',
      'if ($http_user_agent ~* "(sqlmap|nikto|nessus|\\$\\{jndi:)") { return 403; }',
    ],
    awsRegex: '(\\.\\./|%2e%2e|<script|%3cscript|union\\s+select|169\\.254\\.169\\.254|\\$\\{jndi:)',
    awsHeader: 'user-agent',
    awsHeaderRegex: '(sqlmap|nikto|nessus|\\$\\{jndi:)',
  },
}

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

export function modsecRuleId(seed) {
  return 100000 + ((hash(seed) >>> 0) % 900000000)
}

export function generateWafRules(finding = {}) {
  const path = findingPath(finding)
  const escapedPath = escapeRegex(path)
  const kind = family(finding)
  const profile = RULE_PROFILES[kind] || RULE_PROFILES.generic
  const isRootFallback = path === '/'

  const cfPathExpr = isRootFallback
    ? 'http.request.uri.path starts_with "/"'
    : `http.request.uri.path eq "${path}"`
  const expression = `${cfPathExpr} and ${profile.cfCondition}`

  const modsecId = modsecRuleId(`${finding.id || ''}:${finding.title || ''}:${path}:${kind}`)
  const modsecPathOp = isRootFallback ? '@beginsWith /' : `@streq ${path}`
  const modsec = [
    `SecRule REQUEST_URI "${modsecPathOp}" "id:${modsecId},phase:2,deny,status:403,log,msg:'SentinelAI ${profile.label} virtual patch',chain"`,
    `    SecRule ${profile.modsecVars} "@rx ${profile.modsecRx}" "t:none,t:urlDecodeUni"`,
  ].join('\n')

  const nginxLocation = isRootFallback ? 'location /' : `location ~* ^${escapedPath}$`
  const nginx = `${nginxLocation} {\n${profile.nginxChecks.map((line) => `  ${line}`).join('\n')}\n}`

  const inspectionStatements = [
    {
      regexMatchStatement: {
        fieldToMatch: { queryString: {} },
        regexString: profile.awsRegex,
        textTransformations: [{ priority: 0, type: 'URL_DECODE' }, { priority: 1, type: 'LOWERCASE' }],
      },
    },
    {
      regexMatchStatement: {
        fieldToMatch: { body: { oversizeHandling: 'CONTINUE' } },
        regexString: profile.awsRegex,
        textTransformations: [{ priority: 0, type: 'URL_DECODE' }, { priority: 1, type: 'LOWERCASE' }],
      },
    },
  ]
  if (profile.awsHeader) {
    inspectionStatements.push({
      regexMatchStatement: {
        fieldToMatch: { singleHeader: { name: profile.awsHeader } },
        regexString: profile.awsHeaderRegex || profile.awsRegex,
        textTransformations: [{ priority: 0, type: 'LOWERCASE' }],
      },
    })
  }

  return {
    generatedAt: new Date().toISOString(),
    findingId: finding.id || null,
    scope: { path, family: kind },
    warning: 'Review and tune this rule in staging before deployment. This is a compensating control, not a code fix.',
    cloudflare: { action: 'block', expression },
    modSecurity: modsec,
    nginx,
    awsWaf: {
      name: `sentinelai-${kind}-${(hash(`${path}:${kind}`) >>> 0).toString(36)}`,
      statement: {
        andStatement: {
          statements: [
            {
              byteMatchStatement: {
                fieldToMatch: { uriPath: {} },
                positionalConstraint: isRootFallback ? 'STARTS_WITH' : 'EXACTLY',
                searchString: path,
                textTransformations: [{ priority: 0, type: 'NONE' }],
              },
            },
            {
              orStatement: {
                statements: inspectionStatements,
              },
            },
          ],
        },
      },
      action: 'BLOCK',
    },
  }
}

function hash(value) {
  let result = 0
  for (const char of String(value)) result = ((result << 5) - result + char.charCodeAt(0)) | 0
  return result || 1
}

export default { generateWafRules, modsecRuleId }
