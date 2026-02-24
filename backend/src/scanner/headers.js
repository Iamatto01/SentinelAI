import { randomUUID } from 'node:crypto';
import https from 'node:https';
import http from 'node:http';

const SECURITY_HEADERS = [
  {
    header: 'strict-transport-security',
    title: 'Missing HTTP Strict Transport Security (HSTS)',
    severity: 'medium',
    cvss: 5.3,
    cweId: 'CWE-523',
    description: 'The Strict-Transport-Security header is not set. This allows attackers to perform man-in-the-middle attacks by downgrading HTTPS to HTTP.',
    remediation: 'Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
  },
  {
    header: 'content-security-policy',
    title: 'Missing Content-Security-Policy (CSP) Header',
    severity: 'medium',
    cvss: 5.3,
    cweId: 'CWE-1021',
    description: 'No Content-Security-Policy header found. This increases the risk of XSS, clickjacking, and other code injection attacks.',
    remediation: "Add a Content-Security-Policy header, e.g.: Content-Security-Policy: default-src 'self'; script-src 'self'",
  },
  {
    header: 'x-frame-options',
    title: 'Missing X-Frame-Options Header',
    severity: 'medium',
    cvss: 4.3,
    cweId: 'CWE-1021',
    description: 'The X-Frame-Options header is not set, making the site potentially vulnerable to clickjacking attacks.',
    remediation: 'Add the header: X-Frame-Options: DENY or SAMEORIGIN',
  },
  {
    header: 'x-content-type-options',
    title: 'Missing X-Content-Type-Options Header',
    severity: 'low',
    cvss: 3.1,
    cweId: 'CWE-16',
    description: 'The X-Content-Type-Options header is not set to "nosniff". Browsers may MIME-sniff the content, potentially leading to security issues.',
    remediation: 'Add the header: X-Content-Type-Options: nosniff',
  },
  {
    header: 'referrer-policy',
    title: 'Missing Referrer-Policy Header',
    severity: 'low',
    cvss: 2.6,
    cweId: 'CWE-200',
    description: 'No Referrer-Policy header set. The browser may leak sensitive URL information via the Referer header to third-party sites.',
    remediation: 'Add the header: Referrer-Policy: strict-origin-when-cross-origin',
  },
  {
    header: 'permissions-policy',
    title: 'Missing Permissions-Policy Header',
    severity: 'low',
    cvss: 2.6,
    cweId: 'CWE-16',
    description: 'No Permissions-Policy header set. Browser features like camera, microphone, and geolocation are not explicitly restricted.',
    remediation: 'Add the header: Permissions-Policy: camera=(), microphone=(), geolocation=()',
  },
];

function makeFinding(opts, targetUrl) {
  return {
    id: `vuln_${randomUUID()}`,
    title: opts.title,
    severity: opts.severity,
    cvss: opts.cvss,
    cweId: opts.cweId,
    cveIds: opts.cveIds || [],
    status: 'open',
    asset: targetUrl,
    discovered: new Date().toISOString(),
    description: opts.description,
    remediation: opts.remediation,
    module: 'HTTP Headers Analysis',
    aiConfidence: opts.aiConfidence || 0.95,
    aiReasoning: opts.aiReasoning || 'Confirmed from HTTP response analysis',
  };
}

function fetchUrl(url, options = {}) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { timeout: 10000, rejectUnauthorized: false, ...options }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body }));
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
    req.on('error', reject);
  });
}

function optionsRequest(url) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const mod = parsed.protocol === 'https:' ? https : http;
    const req = mod.request({
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname,
      method: 'OPTIONS',
      timeout: 10000,
      rejectUnauthorized: false,
      headers: { Origin: 'https://evil.example.com' },
    }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body }));
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
    req.on('error', reject);
    req.end();
  });
}

export async function scanHeaders(targetUrl, onFinding, onLog) {
  const findings = [];

  onLog?.('info', `Fetching HTTP response from ${targetUrl}`);

  // Fetch the target
  let response;
  try {
    response = await fetchUrl(targetUrl);
  } catch (err) {
    const f = makeFinding({
      title: 'Target Unreachable',
      severity: 'info',
      cvss: 0,
      cweId: 'N/A',
      description: `Could not connect to ${targetUrl}: ${err.message}`,
      remediation: 'Verify the target URL is correct and accessible.',
      aiConfidence: 1.0,
      aiReasoning: 'Connection failed',
    }, targetUrl);
    onLog?.('error', `Target unreachable: ${err.message}`);
    findings.push(f);
    onFinding?.(f);
    return findings;
  }

  const headers = response.headers;

  onLog?.('info', `Received HTTP ${response.statusCode} - analysing ${Object.keys(headers).length} response headers`);

  // Check security headers
  onLog?.('info', 'Checking security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)');
  for (const check of SECURITY_HEADERS) {
    if (!headers[check.header]) {
      const f = makeFinding(check, targetUrl);
      findings.push(f);
      onFinding?.(f);
    }
  }

  // Server information leakage
  onLog?.('info', 'Checking for server information disclosure');
  if (headers['server']) {
    const f = makeFinding({
      title: 'Server Version Information Disclosure',
      severity: 'low',
      cvss: 2.6,
      cweId: 'CWE-200',
      description: `The Server header reveals: "${headers['server']}". This information helps attackers identify the server software and version.`,
      remediation: 'Remove or genericize the Server header to hide version information.',
      aiReasoning: `Server header value: ${headers['server']}`,
    }, targetUrl);
    findings.push(f);
    onFinding?.(f);
  }

  // X-Powered-By leakage
  if (headers['x-powered-by']) {
    const f = makeFinding({
      title: 'Technology Stack Information Disclosure (X-Powered-By)',
      severity: 'low',
      cvss: 2.6,
      cweId: 'CWE-200',
      description: `The X-Powered-By header reveals: "${headers['x-powered-by']}". This exposes the underlying technology stack.`,
      remediation: 'Remove the X-Powered-By header from server responses.',
      aiReasoning: `X-Powered-By value: ${headers['x-powered-by']}`,
    }, targetUrl);
    findings.push(f);
    onFinding?.(f);
  }

  // Cookie security
  onLog?.('info', 'Analysing cookie security attributes');
  const setCookies = headers['set-cookie'];
  if (setCookies) {
    const cookieList = Array.isArray(setCookies) ? setCookies : [setCookies];
    for (const cookie of cookieList) {
      const lower = cookie.toLowerCase();
      const cookieName = cookie.split('=')[0].trim();
      const issues = [];
      if (!lower.includes('httponly')) issues.push('HttpOnly');
      if (!lower.includes('secure')) issues.push('Secure');
      if (!lower.includes('samesite')) issues.push('SameSite');
      if (issues.length > 0) {
        const f = makeFinding({
          title: `Insecure Cookie: "${cookieName}" Missing ${issues.join(', ')} Flag(s)`,
          severity: 'medium',
          cvss: 4.3,
          cweId: 'CWE-614',
          description: `Cookie "${cookieName}" is missing the following security flags: ${issues.join(', ')}. This may expose the cookie to theft or misuse.`,
          remediation: `Set the cookie with: ${issues.map(i => `${i}`).join('; ')} flags.`,
          aiReasoning: `Cookie header: ${cookie.substring(0, 100)}`,
        }, targetUrl);
        findings.push(f);
        onFinding?.(f);
      }
    }
  }

  // CORS check
  onLog?.('info', 'Testing CORS configuration with OPTIONS request');
  try {
    const optRes = await optionsRequest(targetUrl);
    const acao = optRes.headers['access-control-allow-origin'];
    if (acao === '*') {
      const f = makeFinding({
        title: 'CORS Misconfiguration: Wildcard Access-Control-Allow-Origin',
        severity: 'medium',
        cvss: 5.3,
        cweId: 'CWE-942',
        description: 'The server responds with Access-Control-Allow-Origin: *, allowing any website to make cross-origin requests. This may lead to data theft.',
        remediation: 'Restrict Access-Control-Allow-Origin to specific trusted domains instead of using a wildcard.',
        aiReasoning: 'ACAO header set to wildcard (*)',
      }, targetUrl);
      findings.push(f);
      onFinding?.(f);
    }

    // Dangerous HTTP methods
    const allow = optRes.headers['allow'] || '';
    const dangerous = ['PUT', 'DELETE', 'TRACE'].filter((m) => allow.toUpperCase().includes(m));
    if (dangerous.length > 0) {
      const f = makeFinding({
        title: `Dangerous HTTP Methods Enabled: ${dangerous.join(', ')}`,
        severity: 'low',
        cvss: 3.1,
        cweId: 'CWE-16',
        description: `The server allows the following potentially dangerous HTTP methods: ${dangerous.join(', ')}. These may be exploited for unauthorized data modification or information disclosure.`,
        remediation: 'Disable unnecessary HTTP methods (PUT, DELETE, TRACE) on the web server.',
        aiReasoning: `Allow header: ${allow}`,
      }, targetUrl);
      findings.push(f);
      onFinding?.(f);
    }
  } catch {
    // OPTIONS request failed - not necessarily a vulnerability
  }

  onLog?.('info', `Header analysis complete - ${findings.length} issues found`);
  return findings;
}
