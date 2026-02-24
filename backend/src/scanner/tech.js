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
    cveIds: opts.cveIds || [],
    status: 'open',
    asset: targetUrl,
    discovered: new Date().toISOString(),
    description: opts.description,
    remediation: opts.remediation,
    module: 'Technology Detection',
    aiConfidence: opts.aiConfidence || 0.88,
    aiReasoning: opts.aiReasoning || 'Detected from HTTP response fingerprinting',
    evidence: opts.evidence || {},
  };
}

function fetchUrl(url) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { timeout: 10000, rejectUnauthorized: false }, (res) => {
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

// Technology signature database
const HEADER_SIGNATURES = [
  { header: 'x-powered-by', match: /express/i, tech: 'Express.js (Node.js)', category: 'Backend Framework' },
  { header: 'x-powered-by', match: /php/i, tech: 'PHP', category: 'Backend Language' },
  { header: 'x-powered-by', match: /asp\.net/i, tech: 'ASP.NET', category: 'Backend Framework' },
  { header: 'x-powered-by', match: /next\.js/i, tech: 'Next.js', category: 'Frontend Framework' },
  { header: 'server', match: /nginx/i, tech: 'Nginx', category: 'Web Server' },
  { header: 'server', match: /apache/i, tech: 'Apache HTTP Server', category: 'Web Server' },
  { header: 'server', match: /iis/i, tech: 'Microsoft IIS', category: 'Web Server' },
  { header: 'server', match: /cloudflare/i, tech: 'Cloudflare', category: 'CDN/WAF' },
  { header: 'server', match: /litespeed/i, tech: 'LiteSpeed', category: 'Web Server' },
  { header: 'x-aspnet-version', match: /./i, tech: 'ASP.NET', category: 'Backend Framework' },
  { header: 'x-drupal-cache', match: /./i, tech: 'Drupal', category: 'CMS' },
  { header: 'x-generator', match: /drupal/i, tech: 'Drupal', category: 'CMS' },
  { header: 'x-generator', match: /wordpress/i, tech: 'WordPress', category: 'CMS' },
  { header: 'x-shopify-stage', match: /./i, tech: 'Shopify', category: 'E-Commerce' },
  { header: 'x-wix-request-id', match: /./i, tech: 'Wix', category: 'Website Builder' },
  { header: 'cf-ray', match: /./i, tech: 'Cloudflare', category: 'CDN/WAF' },
  { header: 'x-vercel-id', match: /./i, tech: 'Vercel', category: 'Hosting' },
  { header: 'x-amz-request-id', match: /./i, tech: 'Amazon AWS', category: 'Cloud' },
  { header: 'x-cache', match: /cloudfront/i, tech: 'AWS CloudFront', category: 'CDN' },
];

const BODY_SIGNATURES = [
  { pattern: /wp-content|wp-includes/i, tech: 'WordPress', category: 'CMS', cweId: 'CWE-200' },
  { pattern: /Joomla!/i, tech: 'Joomla', category: 'CMS', cweId: 'CWE-200' },
  { pattern: /sites\/default\/files|drupal/i, tech: 'Drupal', category: 'CMS', cweId: 'CWE-200' },
  { pattern: /<meta\s+name="generator"\s+content="([^"]+)"/i, tech: null, category: 'Generator', cweId: 'CWE-200' },
  { pattern: /react/i, tech: 'React', category: 'Frontend Framework', infoOnly: true },
  { pattern: /vue\.js|__vue__/i, tech: 'Vue.js', category: 'Frontend Framework', infoOnly: true },
  { pattern: /angular/i, tech: 'Angular', category: 'Frontend Framework', infoOnly: true },
  { pattern: /jquery/i, tech: 'jQuery', category: 'JavaScript Library', infoOnly: true },
  { pattern: /bootstrap/i, tech: 'Bootstrap', category: 'CSS Framework', infoOnly: true },
  { pattern: /tailwindcss|tailwind/i, tech: 'Tailwind CSS', category: 'CSS Framework', infoOnly: true },
  { pattern: /laravel/i, tech: 'Laravel', category: 'Backend Framework', cweId: 'CWE-200' },
  { pattern: /django/i, tech: 'Django', category: 'Backend Framework', cweId: 'CWE-200' },
  { pattern: /rails/i, tech: 'Ruby on Rails', category: 'Backend Framework', cweId: 'CWE-200' },
];

export async function scanTech(targetUrl, onFinding, onLog) {
  const findings = [];
  const detected = new Map(); // tech -> { category, sources[] }

  onLog?.('info', `Fingerprinting technology stack for ${targetUrl}`);

  let response;
  try {
    response = await fetchUrl(targetUrl);
  } catch (err) {
    onLog?.('error', `Could not fetch target: ${err.message}`);
    return findings;
  }

  const { headers, body } = response;

  // Check headers
  onLog?.('info', 'Analysing response headers for technology signatures');
  for (const sig of HEADER_SIGNATURES) {
    const val = headers[sig.header];
    if (val && sig.match.test(val)) {
      if (!detected.has(sig.tech)) {
        detected.set(sig.tech, { category: sig.category, sources: [] });
      }
      detected.get(sig.tech).sources.push(`Header: ${sig.header}: ${val}`);
    }
  }

  // Check body
  onLog?.('info', 'Analysing HTML body for technology fingerprints');
  for (const sig of BODY_SIGNATURES) {
    const match = body.match(sig.pattern);
    if (match) {
      const tech = sig.tech || (match[1] ? match[1] : 'Unknown Generator');
      if (!detected.has(tech)) {
        detected.set(tech, { category: sig.category, sources: [], infoOnly: sig.infoOnly, cweId: sig.cweId });
      }
      detected.get(tech).sources.push(`HTML body match: ${match[0].substring(0, 80)}`);
    }
  }

  // Check for common security-sensitive cookies
  onLog?.('info', 'Checking cookies for technology hints');
  const cookieHeader = headers['set-cookie'];
  if (cookieHeader) {
    const cookies = Array.isArray(cookieHeader) ? cookieHeader : [cookieHeader];
    const cookieStr = cookies.join('; ');
    if (cookieStr.includes('PHPSESSID')) {
      if (!detected.has('PHP')) detected.set('PHP', { category: 'Backend Language', sources: [] });
      detected.get('PHP').sources.push('Cookie: PHPSESSID');
    }
    if (cookieStr.includes('JSESSIONID')) {
      if (!detected.has('Java')) detected.set('Java', { category: 'Backend Language', sources: [] });
      detected.get('Java').sources.push('Cookie: JSESSIONID');
    }
    if (cookieStr.includes('ASP.NET_SessionId')) {
      if (!detected.has('ASP.NET')) detected.set('ASP.NET', { category: 'Backend Framework', sources: [] });
      detected.get('ASP.NET').sources.push('Cookie: ASP.NET_SessionId');
    }
    if (cookieStr.includes('laravel_session')) {
      if (!detected.has('Laravel')) detected.set('Laravel', { category: 'Backend Framework', sources: [] });
      detected.get('Laravel').sources.push('Cookie: laravel_session');
    }
  }

  // Generate findings
  if (detected.size === 0) {
    onLog?.('info', 'No technology signatures detected');
    return findings;
  }

  // Build full tech stack summary
  const techList = Array.from(detected.entries()).map(([tech, info]) => `${tech} (${info.category})`);
  const evidenceLines = [];
  for (const [tech, info] of detected.entries()) {
    evidenceLines.push(`[${info.category}] ${tech}`);
    for (const src of info.sources) {
      evidenceLines.push(`  - ${src}`);
    }
  }

  // Main finding: technology stack detected
  const f = makeFinding({
    title: `Technology Stack Detected: ${techList.slice(0, 4).join(', ')}${techList.length > 4 ? ` (+${techList.length - 4} more)` : ''}`,
    severity: 'info',
    cvss: 0,
    cweId: 'CWE-200',
    description: `${detected.size} technologies identified on ${targetUrl}: ${techList.join(', ')}. Knowing the technology stack helps attackers find version-specific vulnerabilities.`,
    remediation: 'Remove or obfuscate technology identifiers: Server header, X-Powered-By header, HTML meta generator tags, and framework-specific cookies.',
    aiReasoning: `Detected ${detected.size} technologies from headers, HTML, and cookies`,
    evidence: { type: 'techstack', label: 'Detected Technologies', data: evidenceLines.join('\n') },
  }, targetUrl);
  findings.push(f);
  onFinding?.(f);

  // Individual findings for security-relevant disclosures
  for (const [tech, info] of detected.entries()) {
    if (info.infoOnly) continue;
    // Server/framework version exposure
    const versionSources = info.sources.filter((s) => s.startsWith('Header:'));
    if (versionSources.length > 0) {
      const headerEvidence = versionSources.join('\n');
      const f2 = makeFinding({
        title: `${info.category} Exposed: ${tech}`,
        severity: 'low',
        cvss: 2.6,
        cweId: info.cweId || 'CWE-200',
        description: `The server exposes that it uses ${tech} (${info.category}) via HTTP headers. This helps attackers narrow down attack vectors.`,
        remediation: `Remove or genericize headers that reveal ${tech} usage.`,
        aiReasoning: `${tech} detected via: ${versionSources[0]}`,
        evidence: { type: 'headers', label: `${tech} Detection`, data: headerEvidence },
      }, targetUrl);
      findings.push(f2);
      onFinding?.(f2);
    }
  }

  onLog?.('info', `Technology detection complete - ${detected.size} technologies found, ${findings.length} findings`);
  return findings;
}
