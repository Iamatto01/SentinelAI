import { randomUUID } from 'node:crypto';
import https from 'node:https';
import http from 'node:http';

function makeFinding(opts, targetUrl) {
  return {
    id: `vuln_${randomUUID()}`,
    title: opts.title,
    severity: opts.severity,
    cvss: opts.cvss,
    cweId: opts.cweId || 'CWE-200',
    cveIds: [],
    status: 'open',
    asset: targetUrl,
    discovered: new Date().toISOString(),
    description: opts.description,
    remediation: opts.remediation,
    module: 'Information Disclosure',
    aiConfidence: opts.aiConfidence || 0.90,
    aiReasoning: opts.aiReasoning || 'Detected from HTTP response analysis',
    evidence: opts.evidence || {},
  };
}

function fetchUrl(url, options = {}) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { timeout: 10000, rejectUnauthorized: false, ...options }, (res) => {
      let body = '';
      let collected = 0;
      res.on('data', (c) => {
        collected += c.length;
        if (collected < 65536) body += c;
      });
      res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body }));
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
  });
}

// Paths that commonly leak sensitive information
const SENSITIVE_PATHS = [
  { path: '/robots.txt', name: 'robots.txt', check: 'disallow' },
  { path: '/sitemap.xml', name: 'sitemap.xml', check: 'sitemap' },
  { path: '/security.txt', name: 'security.txt', check: 'security' },
  { path: '/.well-known/security.txt', name: 'security.txt (well-known)', check: 'security' },
  { path: '/humans.txt', name: 'humans.txt', check: 'exists' },
  { path: '/crossdomain.xml', name: 'crossdomain.xml', check: 'crossdomain' },
  { path: '/clientaccesspolicy.xml', name: 'clientaccesspolicy.xml', check: 'exists' },
];

// Error page triggers
const ERROR_TRIGGERS = [
  { path: '/this-page-does-not-exist-sentinel-404-check', name: '404 Error Page' },
  { path: "/?id=1'", name: 'SQL Error Probe' },
  { path: '/<script>', name: 'XSS Error Probe' },
];

const STACK_TRACE_PATTERNS = [
  { pattern: /at\s+\S+\s+\([\w/\\.:]+:\d+:\d+\)/i, tech: 'Node.js/JavaScript' },
  { pattern: /Traceback \(most recent call last\)/i, tech: 'Python' },
  { pattern: /Fatal error:.*on line \d+/i, tech: 'PHP' },
  { pattern: /java\.\w+\.\w+Exception/i, tech: 'Java' },
  { pattern: /Microsoft\.AspNetCore|System\.NullReferenceException/i, tech: 'ASP.NET' },
  { pattern: /ActionController::RoutingError|ActiveRecord/i, tech: 'Ruby on Rails' },
  { pattern: /Laravel|Symfony\\Component/i, tech: 'PHP (Laravel/Symfony)' },
  { pattern: /SQLSTATE\[/i, tech: 'SQL Database' },
  { pattern: /MySQL|MariaDB/i, tech: 'MySQL/MariaDB' },
  { pattern: /PostgreSQL|psql/i, tech: 'PostgreSQL' },
];

export async function scanInfo(targetUrl, onFinding, onLog) {
  const findings = [];

  onLog?.('info', `Starting information disclosure scan for ${targetUrl}`);

  // === Test 1: Check robots.txt for sensitive disallows ===
  onLog?.('info', 'Checking robots.txt for sensitive path disclosures');
  try {
    const robotsUrl = new URL('/robots.txt', targetUrl).href;
    const res = await fetchUrl(robotsUrl);
    if (res.statusCode === 200 && res.body.length > 10) {
      const lines = res.body.split('\n');
      const disallowed = lines
        .filter((l) => /^disallow:/i.test(l.trim()))
        .map((l) => l.replace(/^disallow:\s*/i, '').trim())
        .filter(Boolean);

      const sensitive = disallowed.filter((p) =>
        /admin|login|api|internal|private|secret|backup|config|database|phpmyadmin|wp-admin|\.env|\.git|dashboard|manage/i.test(p)
      );

      if (sensitive.length > 0) {
        const f = makeFinding({
          title: `robots.txt Reveals ${sensitive.length} Sensitive Paths`,
          severity: 'low',
          cvss: 3.7,
          cweId: 'CWE-200',
          description: `The robots.txt file disallows crawling of ${sensitive.length} potentially sensitive paths. While robots.txt prevents search engine indexing, it publicly reveals internal path structure to attackers.`,
          remediation: 'Avoid listing sensitive internal paths in robots.txt. Use authentication and access controls instead of relying on obscurity.',
          aiReasoning: `Found ${sensitive.length} sensitive disallowed paths in robots.txt`,
          evidence: { type: 'http', label: 'robots.txt Analysis', data: `Sensitive disallowed paths:\n${sensitive.map((p) => `  Disallow: ${p}`).join('\n')}\n\nFull robots.txt:\n${res.body.substring(0, 2000)}` },
        }, targetUrl);
        findings.push(f);
        onFinding?.(f);
      }
    }
  } catch { /* failed */ }

  // === Test 2: Check error pages for stack traces / version leak ===
  onLog?.('info', 'Testing error responses for information leakage');
  for (const trigger of ERROR_TRIGGERS) {
    try {
      const errUrl = new URL(trigger.path, targetUrl).href;
      const res = await fetchUrl(errUrl);

      // Check for stack traces
      for (const pat of STACK_TRACE_PATTERNS) {
        if (pat.pattern.test(res.body)) {
          const match = res.body.match(pat.pattern);
          const snippet = res.body.substring(
            Math.max(0, res.body.indexOf(match[0]) - 100),
            Math.min(res.body.length, res.body.indexOf(match[0]) + match[0].length + 200)
          );

          const f = makeFinding({
            title: `Stack Trace Exposed in Error Response (${pat.tech})`,
            severity: 'medium',
            cvss: 5.3,
            cweId: 'CWE-209',
            description: `The server returns detailed error information including ${pat.tech} stack traces when triggered with ${trigger.name}. Stack traces reveal internal file paths, framework versions, and code structure.`,
            remediation: 'Configure custom error pages for production. Disable debug mode and detailed error reporting. Use generic error messages for end users.',
            aiReasoning: `${pat.tech} stack trace detected in response to ${trigger.path}`,
            evidence: { type: 'http', label: `Error Page - ${trigger.name}`, data: `Request: GET ${trigger.path}\nStatus: ${res.statusCode}\n\nStack trace snippet:\n${snippet}` },
          }, targetUrl);
          findings.push(f);
          onFinding?.(f);
          break; // One finding per error trigger
        }
      }

      // Check for debug mode indicators
      if (/debug\s*=\s*true|DEBUG_MODE|development mode|Laravel.*debug/i.test(res.body)) {
        const f = makeFinding({
          title: 'Application Running in Debug Mode',
          severity: 'high',
          cvss: 7.5,
          cweId: 'CWE-215',
          description: 'The application appears to be running in debug/development mode in production. Debug mode typically exposes detailed error messages, environment variables, database credentials, and internal application state.',
          remediation: 'Disable debug mode in production. Set environment to "production" and configure proper error handling.',
          aiReasoning: 'Debug mode indicator found in error response body',
          evidence: { type: 'http', label: 'Debug Mode Detection', data: `Request: GET ${trigger.path}\nStatus: ${res.statusCode}\n\nResponse snippet:\n${res.body.substring(0, 1500)}` },
        }, targetUrl);
        findings.push(f);
        onFinding?.(f);
      }
    } catch { /* failed */ }
  }

  // === Test 3: Check common info files ===
  onLog?.('info', 'Checking for information disclosure files');
  for (const item of SENSITIVE_PATHS) {
    if (item.path === '/robots.txt') continue; // Already checked
    try {
      const checkUrl = new URL(item.path, targetUrl).href;
      const res = await fetchUrl(checkUrl);
      if (res.statusCode === 200 && res.body.length > 10) {
        if (item.check === 'crossdomain') {
          // Check for overly permissive crossdomain.xml
          if (/<allow-access-from\s+domain="\*"/i.test(res.body)) {
            const f = makeFinding({
              title: 'Overly Permissive crossdomain.xml',
              severity: 'medium',
              cvss: 5.3,
              cweId: 'CWE-942',
              description: 'The crossdomain.xml file allows access from any domain (domain="*"). This permits Flash/Silverlight-based cross-origin requests from any website.',
              remediation: 'Restrict crossdomain.xml to specific trusted domains instead of using wildcard.',
              aiReasoning: 'crossdomain.xml contains domain="*"',
              evidence: { type: 'http', label: 'crossdomain.xml', data: `GET ${item.path}\n\n${res.body.substring(0, 1000)}` },
            }, targetUrl);
            findings.push(f);
            onFinding?.(f);
          }
        } else if (item.check === 'sitemap') {
          // Check sitemap for internal/sensitive URLs
          const internalPatterns = /admin|internal|private|api|staging|dev|test|dashboard|manage|config/i;
          const urls = res.body.match(/<loc>([^<]+)<\/loc>/gi) || [];
          const sensitiveUrls = urls
            .map((u) => u.replace(/<\/?loc>/gi, ''))
            .filter((u) => internalPatterns.test(u));
          if (sensitiveUrls.length > 0) {
            const f = makeFinding({
              title: `Sitemap Reveals ${sensitiveUrls.length} Sensitive URLs`,
              severity: 'low',
              cvss: 3.7,
              cweId: 'CWE-200',
              description: `The sitemap.xml reveals ${sensitiveUrls.length} URLs matching sensitive patterns (admin, internal, api, etc.). This helps attackers map internal application structure.`,
              remediation: 'Exclude sensitive and internal URLs from sitemap.xml.',
              aiReasoning: `Found ${sensitiveUrls.length} sensitive URLs in sitemap.xml`,
              evidence: { type: 'http', label: 'Sitemap Analysis', data: `Sensitive URLs found:\n${sensitiveUrls.slice(0, 20).join('\n')}` },
            }, targetUrl);
            findings.push(f);
            onFinding?.(f);
          }
        }
      }
    } catch { /* failed */ }
  }

  // === Test 4: Check for server header version disclosure ===
  onLog?.('info', 'Checking response headers for version information');
  try {
    const res = await fetchUrl(targetUrl);
    const versionHeaders = [];

    // Check for detailed version in Server header
    const server = res.headers['server'] || '';
    if (/\d+\.\d+/.test(server)) {
      versionHeaders.push(`Server: ${server}`);
    }

    // Check X-Powered-By for version
    const poweredBy = res.headers['x-powered-by'] || '';
    if (/\d+\.\d+/.test(poweredBy)) {
      versionHeaders.push(`X-Powered-By: ${poweredBy}`);
    }

    // Check X-AspNet-Version
    const aspnet = res.headers['x-aspnet-version'];
    if (aspnet) versionHeaders.push(`X-AspNet-Version: ${aspnet}`);

    // Check X-AspNetMvc-Version
    const aspnetMvc = res.headers['x-aspnetmvc-version'];
    if (aspnetMvc) versionHeaders.push(`X-AspNetMvc-Version: ${aspnetMvc}`);

    if (versionHeaders.length > 0) {
      const f = makeFinding({
        title: `Server Version Disclosed in HTTP Headers`,
        severity: 'low',
        cvss: 3.7,
        cweId: 'CWE-200',
        description: `The server exposes specific version numbers in HTTP response headers: ${versionHeaders.join(', ')}. Version information helps attackers find known CVEs for the exact software version.`,
        remediation: 'Remove or genericize version information from Server, X-Powered-By, and other version-revealing headers.',
        aiReasoning: `Version information leaked via ${versionHeaders.length} header(s)`,
        evidence: { type: 'headers', label: 'Version Disclosure', data: `Version-revealing headers:\n${versionHeaders.join('\n')}\n\nAll response headers:\n${Object.entries(res.headers).map(([k, v]) => `${k}: ${v}`).join('\n')}` },
      }, targetUrl);
      findings.push(f);
      onFinding?.(f);
    }

    // === Test 5: Check HTML comments for sensitive info ===
    onLog?.('info', 'Scanning HTML for sensitive comments and metadata');
    const comments = res.body.match(/<!--[\s\S]*?-->/g) || [];
    const sensitiveComments = comments.filter((c) =>
      /password|secret|key|token|api[_-]?key|TODO|FIXME|HACK|BUG|credential|internal|private|database|connection.?string/i.test(c)
    );

    if (sensitiveComments.length > 0) {
      const f = makeFinding({
        title: `${sensitiveComments.length} Sensitive HTML Comments Found`,
        severity: 'low',
        cvss: 3.7,
        cweId: 'CWE-615',
        description: `Found ${sensitiveComments.length} HTML comments containing potentially sensitive keywords (passwords, API keys, TODO notes, internal references). Comments are visible in page source.`,
        remediation: 'Remove all sensitive comments from production HTML. Use server-side comments or build tools to strip comments before deployment.',
        aiReasoning: `Found comments matching sensitive patterns: ${sensitiveComments.length}`,
        evidence: { type: 'http', label: 'Sensitive Comments', data: sensitiveComments.slice(0, 10).map((c) => c.substring(0, 200)).join('\n\n') },
      }, targetUrl);
      findings.push(f);
      onFinding?.(f);
    }

    // === Test 6: Check for email addresses in source ===
    const emails = res.body.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [];
    const uniqueEmails = [...new Set(emails)].filter((e) => !/@example\.com|@test\.com|@placeholder/i.test(e));
    if (uniqueEmails.length > 2) {
      const f = makeFinding({
        title: `${uniqueEmails.length} Email Addresses Exposed in HTML Source`,
        severity: 'info',
        cvss: 0,
        cweId: 'CWE-200',
        description: `Found ${uniqueEmails.length} unique email addresses in the page source. Exposed emails can be harvested for phishing and social engineering attacks.`,
        remediation: 'Avoid embedding email addresses directly in HTML. Use contact forms or obfuscation techniques.',
        aiReasoning: `${uniqueEmails.length} unique email addresses found in HTML source`,
        evidence: { type: 'http', label: 'Email Addresses', data: uniqueEmails.slice(0, 20).join('\n') },
      }, targetUrl);
      findings.push(f);
      onFinding?.(f);
    }
  } catch (err) {
    onLog?.('warn', `Failed to fetch target for header/comment analysis: ${err.message}`);
  }

  if (findings.length === 0) {
    onLog?.('info', 'No information disclosure issues found');
  }

  onLog?.('info', `Information disclosure scan complete - ${findings.length} findings`);
  return findings;
}
