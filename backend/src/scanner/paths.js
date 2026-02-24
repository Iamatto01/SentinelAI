import { randomUUID } from 'node:crypto';
import https from 'node:https';
import http from 'node:http';

const PROBE_PATHS = [
  { path: '/.env', desc: 'Environment configuration file', severity: 'critical', cvss: 9.1, cwe: 'CWE-538' },
  { path: '/.git/HEAD', desc: 'Git repository metadata', severity: 'high', cvss: 7.5, cwe: 'CWE-538' },
  { path: '/.git/config', desc: 'Git config file', severity: 'high', cvss: 7.5, cwe: 'CWE-538' },
  { path: '/robots.txt', desc: 'Robots exclusion file (info only)', severity: 'info', cvss: 0, cwe: 'CWE-200', infoOnly: true },
  { path: '/sitemap.xml', desc: 'Sitemap file (info only)', severity: 'info', cvss: 0, cwe: 'CWE-200', infoOnly: true },
  { path: '/.DS_Store', desc: 'macOS directory listing file', severity: 'low', cvss: 3.1, cwe: 'CWE-538' },
  { path: '/.htaccess', desc: 'Apache configuration file', severity: 'medium', cvss: 5.3, cwe: 'CWE-538' },
  { path: '/wp-login.php', desc: 'WordPress login page', severity: 'medium', cvss: 5.3, cwe: 'CWE-200' },
  { path: '/wp-admin/', desc: 'WordPress admin panel', severity: 'medium', cvss: 5.3, cwe: 'CWE-200' },
  { path: '/phpinfo.php', desc: 'PHP information disclosure', severity: 'medium', cvss: 5.3, cwe: 'CWE-200' },
  { path: '/server-status', desc: 'Apache server-status page', severity: 'medium', cvss: 5.3, cwe: 'CWE-200' },
  { path: '/backup.zip', desc: 'Backup archive file', severity: 'critical', cvss: 9.1, cwe: 'CWE-538' },
  { path: '/backup.sql', desc: 'Database backup file', severity: 'critical', cvss: 9.1, cwe: 'CWE-538' },
  { path: '/database.sql', desc: 'Database dump file', severity: 'critical', cvss: 9.1, cwe: 'CWE-538' },
  { path: '/config.php', desc: 'PHP config file', severity: 'high', cvss: 7.5, cwe: 'CWE-538' },
  { path: '/web.config', desc: 'IIS configuration file', severity: 'high', cvss: 7.5, cwe: 'CWE-538' },
  { path: '/.well-known/security.txt', desc: 'Security contact file (info only)', severity: 'info', cvss: 0, cwe: 'CWE-200', infoOnly: true },
  { path: '/crossdomain.xml', desc: 'Flash cross-domain policy', severity: 'low', cvss: 3.1, cwe: 'CWE-942' },
  { path: '/admin/', desc: 'Admin panel', severity: 'medium', cvss: 5.3, cwe: 'CWE-200' },
  { path: '/login', desc: 'Login page', severity: 'info', cvss: 0, cwe: 'CWE-200', infoOnly: true },
];

function makeFinding(opts, targetUrl) {
  return {
    id: `vuln_${randomUUID()}`,
    title: opts.title,
    severity: opts.severity,
    cvss: opts.cvss,
    cweId: opts.cweId,
    cveIds: [],
    status: 'open',
    asset: targetUrl + opts.path,
    discovered: new Date().toISOString(),
    description: opts.description,
    remediation: opts.remediation,
    module: 'Exposed Paths Check',
    aiConfidence: opts.aiConfidence || 0.92,
    aiReasoning: opts.aiReasoning || 'Path returned accessible HTTP status',
  };
}

function probeUrl(url) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { timeout: 8000, rejectUnauthorized: false }, (res) => {
      let body = '';
      let collected = 0;
      res.on('data', (c) => {
        collected += c.length;
        if (collected < 2048) body += c;
      });
      res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body }));
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
  });
}

async function probePath(baseUrl, probe) {
  const url = baseUrl.replace(/\/+$/, '') + probe.path;
  try {
    const res = await probeUrl(url);
    if (res.statusCode === 200) {
      return { found: true, statusCode: res.statusCode, body: res.body, probe };
    }
    if ([301, 302, 307, 308].includes(res.statusCode) && !probe.infoOnly) {
      return { found: true, statusCode: res.statusCode, body: '', probe };
    }
  } catch {
    // unreachable or timed out
  }
  return { found: false, probe };
}

export async function scanPaths(targetUrl, onFinding, onLog) {
  const findings = [];
  const baseUrl = targetUrl.replace(/\/+$/, '');

  onLog?.('info', `Probing ${PROBE_PATHS.length} sensitive paths on ${baseUrl}`);

  // Run probes with concurrency limit of 5
  const results = [];
  for (let i = 0; i < PROBE_PATHS.length; i += 5) {
    const batch = PROBE_PATHS.slice(i, i + 5).map((p) => probePath(baseUrl, p));
    onLog?.('info', `Checking paths batch ${Math.floor(i / 5) + 1}/${Math.ceil(PROBE_PATHS.length / 5)}: ${PROBE_PATHS.slice(i, i + 5).map((p) => p.path).join(', ')}`);
    const batchResults = await Promise.allSettled(batch);
    for (const r of batchResults) {
      if (r.status === 'fulfilled') results.push(r.value);
    }
  }

  for (const result of results) {
    if (!result.found) continue;
    const p = result.probe;

    if (p.infoOnly) {
      // Info-only findings (robots.txt, sitemap, etc.)
      const f = makeFinding({
        title: `Accessible: ${p.desc}`,
        severity: 'info',
        cvss: 0,
        cweId: p.cwe,
        path: p.path,
        description: `The file at ${p.path} is publicly accessible (HTTP ${result.statusCode}). ${p.desc}.`,
        remediation: 'Review whether this file should be publicly accessible.',
        aiConfidence: 0.99,
        aiReasoning: `HTTP ${result.statusCode} returned for ${p.path}`,
      }, baseUrl);
      findings.push(f);
      onFinding?.(f);
    } else {
      const f = makeFinding({
        title: `Exposed Sensitive File: ${p.path}`,
        severity: p.severity,
        cvss: p.cvss,
        cweId: p.cwe,
        path: p.path,
        description: `The path ${p.path} (${p.desc}) is accessible on the server (HTTP ${result.statusCode}). This may expose sensitive information to attackers.`,
        remediation: `Restrict access to ${p.path} by configuring the web server to deny requests, or remove the file if not needed.`,
        aiConfidence: result.statusCode === 200 ? 0.97 : 0.75,
        aiReasoning: `HTTP ${result.statusCode} returned for ${p.path}`,
      }, baseUrl);
      findings.push(f);
      onFinding?.(f);
    }
  }

  const accessibleCount = results.filter((r) => r.found).length;
  onLog?.('info', `Path probing complete - ${accessibleCount} accessible paths, ${findings.length} findings`);
  return findings;
}
