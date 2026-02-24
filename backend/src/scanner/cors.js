import { randomUUID } from 'node:crypto';
import https from 'node:https';
import http from 'node:http';

function makeFinding(opts, targetUrl) {
  return {
    id: `vuln_${randomUUID()}`,
    title: opts.title,
    severity: opts.severity,
    cvss: opts.cvss,
    cweId: opts.cweId,
    cveIds: [],
    status: 'open',
    asset: targetUrl,
    discovered: new Date().toISOString(),
    description: opts.description,
    remediation: opts.remediation,
    module: 'CORS Misconfiguration',
    aiConfidence: opts.aiConfidence || 0.93,
    aiReasoning: opts.aiReasoning || 'Confirmed from CORS response analysis',
    evidence: opts.evidence || {},
  };
}

function corsRequest(url, origin) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const mod = parsed.protocol === 'https:' ? https : http;
    const req = mod.request({
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname || '/',
      method: 'OPTIONS',
      timeout: 10000,
      rejectUnauthorized: false,
      headers: { Origin: origin, 'Access-Control-Request-Method': 'GET' },
    }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers }));
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
    req.end();
  });
}

function getRequest(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { timeout: 10000, rejectUnauthorized: false, headers }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body }));
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
  });
}

function formatCorsHeaders(headers) {
  return Object.entries(headers)
    .filter(([k]) => k.toLowerCase().startsWith('access-control'))
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n') || '(no CORS headers)';
}

export async function scanCors(targetUrl, onFinding, onLog) {
  const findings = [];

  onLog?.('info', `Testing CORS configuration for ${targetUrl}`);

  // Test 1: Wildcard origin
  onLog?.('info', 'Test 1: Checking for wildcard Access-Control-Allow-Origin');
  try {
    const res = await getRequest(targetUrl, { Origin: 'https://evil-attacker.com' });
    const acao = res.headers['access-control-allow-origin'];
    const acac = res.headers['access-control-allow-credentials'];

    if (acao === '*') {
      const f = makeFinding({
        title: 'CORS: Wildcard Origin Allowed',
        severity: 'medium',
        cvss: 5.3,
        cweId: 'CWE-942',
        description: 'The server responds with Access-Control-Allow-Origin: * allowing any website to read responses. If sensitive data is served, it can be stolen cross-origin.',
        remediation: 'Replace wildcard with specific trusted origins. Never use * with credentials.',
        aiReasoning: 'ACAO set to * in response',
        evidence: { type: 'headers', label: 'CORS Test — Wildcard', data: `Request Origin: https://evil-attacker.com\n\nResponse:\n${formatCorsHeaders(res.headers)}` },
      }, targetUrl);
      findings.push(f);
      onFinding?.(f);
    }

    // Test 2: Reflected origin
    if (acao === 'https://evil-attacker.com') {
      const sev = acac === 'true' ? 'critical' : 'high';
      const f = makeFinding({
        title: acac === 'true' ? 'CORS: Reflected Origin with Credentials' : 'CORS: Origin Reflection (Any Origin Accepted)',
        severity: sev,
        cvss: acac === 'true' ? 9.1 : 7.5,
        cweId: 'CWE-942',
        description: acac === 'true'
          ? `The server reflects any Origin and allows credentials. An attacker's website can make authenticated requests and steal sensitive data from logged-in users.`
          : `The server reflects any Origin value back in Access-Control-Allow-Origin. Any website can read cross-origin responses from this server.`,
        remediation: 'Validate the Origin header against a whitelist of trusted domains. Never reflect arbitrary origins.',
        aiReasoning: `Origin reflected: ${acao}, credentials: ${acac}`,
        evidence: { type: 'headers', label: 'CORS Test — Origin Reflection', data: `Request Origin: https://evil-attacker.com\n\nResponse:\n${formatCorsHeaders(res.headers)}` },
      }, targetUrl);
      findings.push(f);
      onFinding?.(f);
    }
  } catch (err) {
    onLog?.('warn', `GET with custom origin failed: ${err.message}`);
  }

  // Test 3: Null origin
  onLog?.('info', 'Test 2: Checking for null origin acceptance');
  try {
    const res = await getRequest(targetUrl, { Origin: 'null' });
    const acao = res.headers['access-control-allow-origin'];
    if (acao === 'null') {
      const f = makeFinding({
        title: 'CORS: Null Origin Accepted',
        severity: 'high',
        cvss: 7.5,
        cweId: 'CWE-942',
        description: 'The server accepts "null" as a valid origin. Sandboxed iframes and local file:// pages send Origin: null, allowing attackers to bypass CORS restrictions.',
        remediation: 'Never trust the "null" origin. Remove it from your CORS whitelist.',
        aiReasoning: `ACAO responds with null when Origin: null is sent`,
        evidence: { type: 'headers', label: 'CORS Test — Null Origin', data: `Request Origin: null\n\nResponse:\n${formatCorsHeaders(res.headers)}` },
      }, targetUrl);
      findings.push(f);
      onFinding?.(f);
    }
  } catch { /* failed */ }

  // Test 4: Subdomain trust
  onLog?.('info', 'Test 3: Checking for subdomain/prefix trust');
  try {
    const parsed = new URL(targetUrl);
    const evilSub = `https://evil.${parsed.hostname}`;
    const res = await getRequest(targetUrl, { Origin: evilSub });
    const acao = res.headers['access-control-allow-origin'];
    if (acao === evilSub) {
      const f = makeFinding({
        title: 'CORS: Arbitrary Subdomain Trusted',
        severity: 'medium',
        cvss: 5.3,
        cweId: 'CWE-942',
        description: `The server trusts any subdomain of ${parsed.hostname}. If an attacker compromises any subdomain (e.g., via subdomain takeover), they can steal data cross-origin.`,
        remediation: 'Validate the full Origin hostname, not just the base domain. Only trust specific known subdomains.',
        aiReasoning: `Subdomain origin ${evilSub} was reflected`,
        evidence: { type: 'headers', label: 'CORS Test — Subdomain', data: `Request Origin: ${evilSub}\n\nResponse:\n${formatCorsHeaders(res.headers)}` },
      }, targetUrl);
      findings.push(f);
      onFinding?.(f);
    }
  } catch { /* failed */ }

  // Test 5: Pre-flight check
  onLog?.('info', 'Test 4: Testing preflight OPTIONS response');
  try {
    const res = await corsRequest(targetUrl, 'https://evil-attacker.com');
    const acam = res.headers['access-control-allow-methods'];
    if (acam) {
      const methods = acam.split(',').map((m) => m.trim().toUpperCase());
      const dangerous = methods.filter((m) => ['PUT', 'DELETE', 'PATCH'].includes(m));
      if (dangerous.length > 0) {
        const f = makeFinding({
          title: `CORS Preflight Allows Dangerous Methods: ${dangerous.join(', ')}`,
          severity: 'medium',
          cvss: 5.3,
          cweId: 'CWE-942',
          description: `The CORS preflight response allows ${dangerous.join(', ')} methods from cross-origin requests. This could enable attackers to modify data.`,
          remediation: 'Limit Access-Control-Allow-Methods to only the HTTP methods your API actually needs for cross-origin requests.',
          aiReasoning: `Preflight allows: ${acam}`,
          evidence: { type: 'headers', label: 'CORS Preflight Response', data: `OPTIONS request from Origin: https://evil-attacker.com\n\nResponse:\n${formatCorsHeaders(res.headers)}` },
        }, targetUrl);
        findings.push(f);
        onFinding?.(f);
      }
    }
  } catch { /* failed */ }

  if (findings.length === 0) {
    onLog?.('info', 'No CORS misconfigurations found');
  }

  onLog?.('info', `CORS analysis complete - ${findings.length} issues found`);
  return findings;
}
