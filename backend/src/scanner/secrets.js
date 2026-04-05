import { randomUUID } from 'node:crypto';
import https from 'node:https';
import http from 'node:http';

const SECRET_PATTERNS = [
  {
    name: 'Private Key Material',
    regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g,
    severity: 'critical',
    cvss: 9.1,
    cweId: 'CWE-798',
    remediation: 'Remove private keys from client-delivered assets and rotate any exposed keys immediately.',
  },
  {
    name: 'AWS Access Key ID',
    regex: /AKIA[0-9A-Z]{16}/g,
    severity: 'high',
    cvss: 7.5,
    cweId: 'CWE-798',
    remediation: 'Move cloud credentials to secure server-side secret storage and rotate exposed keys.',
  },
  {
    name: 'Google API Key',
    regex: /AIza[0-9A-Za-z\-_]{35}/g,
    severity: 'medium',
    cvss: 5.3,
    cweId: 'CWE-798',
    remediation: 'Restrict API key by domain, API scope, and quota. Remove key from public JavaScript when possible.',
  },
  {
    name: 'Stripe Live Secret Key',
    regex: /sk_live_[0-9a-zA-Z]{20,}/g,
    severity: 'high',
    cvss: 8,
    cweId: 'CWE-798',
    remediation: 'Never expose Stripe secret keys in frontend assets. Rotate the key and use backend tokenization flows.',
  },
  {
    name: 'Hardcoded JWT Token',
    regex: /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
    severity: 'medium',
    cvss: 5.3,
    cweId: 'CWE-798',
    remediation: 'Do not embed long-lived JWTs in frontend code. Issue short-lived tokens server-side and rotate regularly.',
  },
  {
    name: 'Hardcoded Credential-Like Token',
    regex: /(?:api[_-]?key|secret|token|client[_-]?secret)\s*[:=]\s*["'][A-Za-z0-9_\-\/+={}.]{20,}["']/gi,
    severity: 'medium',
    cvss: 5.3,
    cweId: 'CWE-798',
    remediation: 'Move secrets to server-side configuration and avoid shipping credential-like values in client code.',
  },
];

function makeFinding(opts, asset) {
  return {
    id: `vuln_${randomUUID()}`,
    title: opts.title,
    severity: opts.severity,
    cvss: opts.cvss,
    cweId: opts.cweId,
    cveIds: [],
    status: 'open',
    asset,
    discovered: new Date().toISOString(),
    description: opts.description,
    remediation: opts.remediation,
    module: 'Client-Side Secrets Exposure',
    aiConfidence: opts.aiConfidence || 0.86,
    aiReasoning: opts.aiReasoning || 'Pattern-based secret detection in client-delivered assets.',
    evidence: opts.evidence || {},
  };
}

function requestUrl(url) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const mod = parsed.protocol === 'https:' ? https : http;
    const req = mod.request(
      {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: `${parsed.pathname}${parsed.search}`,
        method: 'GET',
        timeout: 10000,
        rejectUnauthorized: false,
      },
      (res) => {
        let body = '';
        let collected = 0;
        res.on('data', (chunk) => {
          collected += chunk.length;
          if (collected < 262144) body += chunk;
        });
        res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body }));
      },
    );

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('timeout'));
    });
    req.on('error', reject);
    req.end();
  });
}

function extractSameOriginScripts(html, targetUrl) {
  const target = new URL(targetUrl);
  const scripts = new Set();
  const regex = /<script[^>]+src=["']([^"']+)["']/gi;
  let match;

  while ((match = regex.exec(html)) !== null) {
    const src = match[1];
    try {
      const resolved = new URL(src, targetUrl);
      if (resolved.hostname === target.hostname) {
        scripts.add(resolved.href);
      }
    } catch {
      // Ignore malformed script URL.
    }
  }

  return Array.from(scripts);
}

function safeSnippet(text, index, width = 180) {
  const value = String(text || '');
  const start = Math.max(0, index - width);
  const end = Math.min(value.length, index + width);
  return value.slice(start, end).replace(/\s+/g, ' ').trim();
}

function collectMatches(content, sourceRegex, maxMatches = 3) {
  const regex = new RegExp(sourceRegex.source, sourceRegex.flags);
  const hits = [];
  let match;

  while ((match = regex.exec(content)) !== null && hits.length < maxMatches) {
    const value = match[0];
    const snippet = safeSnippet(content, match.index);
    hits.push({ value, snippet });
  }

  return hits;
}

export async function scanSecrets(targetUrl, onFinding, onLog) {
  const findings = [];
  const baseUrl = targetUrl.replace(/\/+$/, '');
  const maxScripts = Math.max(4, Number(process.env.SECRETS_MAX_SCRIPTS || 10));

  onLog?.('info', `Starting client-side secret exposure checks for ${baseUrl}`);

  let mainPage;
  try {
    mainPage = await requestUrl(baseUrl);
  } catch (err) {
    onLog?.('warn', `Could not fetch target page for secret checks: ${err.message}`);
    return findings;
  }

  if (mainPage.statusCode < 200 || mainPage.statusCode >= 500) {
    onLog?.('warn', `Target returned HTTP ${mainPage.statusCode}; skipping deeper client-side secret checks`);
    return findings;
  }

  const scriptUrls = extractSameOriginScripts(mainPage.body, baseUrl).slice(0, maxScripts);
  const sources = [{ label: 'Main HTML', url: baseUrl, content: mainPage.body }];

  if (scriptUrls.length > 0) {
    onLog?.('info', `Inspecting ${scriptUrls.length} same-origin JavaScript assets for hardcoded secrets`);
  }

  for (const scriptUrl of scriptUrls) {
    try {
      const res = await requestUrl(scriptUrl);
      if (res.statusCode === 200) {
        sources.push({ label: `JavaScript Asset (${new URL(scriptUrl).pathname})`, url: scriptUrl, content: res.body });
      }
    } catch {
      // Ignore script fetch failures.
    }
  }

  for (const source of sources) {
    for (const pattern of SECRET_PATTERNS) {
      const hits = collectMatches(source.content, pattern.regex, 3);
      if (hits.length === 0) continue;

      const finding = makeFinding(
        {
          title: `${pattern.name} Exposed in Client Asset`,
          severity: pattern.severity,
          cvss: pattern.cvss,
          cweId: pattern.cweId,
          description: `Detected ${hits.length} match(es) for ${pattern.name} in a client-delivered asset. Public exposure can enable credential abuse or lateral movement.`,
          remediation: pattern.remediation,
          aiReasoning: `${pattern.name} pattern matched in ${source.url}`,
          evidence: {
            type: 'code',
            label: source.label,
            data: hits
              .map((h, idx) => `Match ${idx + 1}: ${h.value}\nContext: ${h.snippet}`)
              .join('\n\n'),
          },
        },
        source.url,
      );
      findings.push(finding);
      onFinding?.(finding);
    }
  }

  onLog?.('info', 'Checking for publicly exposed source maps');
  for (const scriptUrl of scriptUrls) {
    const mapUrl = scriptUrl.endsWith('.map') ? scriptUrl : `${scriptUrl}.map`;
    try {
      const mapRes = await requestUrl(mapUrl);
      if (mapRes.statusCode === 200 && /"sources"\s*:/i.test(mapRes.body)) {
        const finding = makeFinding(
          {
            title: 'Source Map File Publicly Accessible',
            severity: 'low',
            cvss: 3.1,
            cweId: 'CWE-200',
            description: 'A source map file is publicly accessible and may expose original source structure and sensitive implementation details.',
            remediation: 'Do not publish source maps in production unless intentionally required and reviewed.',
            aiReasoning: `${new URL(mapUrl).pathname} returned HTTP 200 and contains source map fields`,
            evidence: {
              type: 'http',
              label: 'Source Map Exposure',
              data: `GET ${new URL(mapUrl).pathname} -> HTTP 200\n\n${safeSnippet(mapRes.body, 0, 300)}`,
            },
          },
          mapUrl,
        );
        findings.push(finding);
        onFinding?.(finding);
      }
    } catch {
      // Ignore map fetch failures.
    }
  }

  onLog?.('info', `Client-side secret checks complete - ${findings.length} findings`);
  return findings;
}
