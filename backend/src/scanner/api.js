import { randomUUID } from 'node:crypto';
import https from 'node:https';
import http from 'node:http';

const API_PROBES = [
  {
    path: '/openapi.json',
    title: 'OpenAPI Specification Exposed',
    severity: 'medium',
    cvss: 5.3,
    cweId: 'CWE-200',
    description: 'The OpenAPI specification is publicly accessible. It may expose internal endpoints, request schemas, and authentication details to attackers.',
    remediation: 'Restrict API documentation endpoints to authenticated users or trusted IP ranges.',
  },
  {
    path: '/swagger.json',
    title: 'Swagger Documentation Endpoint Exposed',
    severity: 'medium',
    cvss: 5.3,
    cweId: 'CWE-200',
    description: 'A Swagger API schema endpoint is publicly accessible and reveals API surface area to unauthenticated users.',
    remediation: 'Protect Swagger endpoints with authentication or disable them in production.',
  },
  {
    path: '/swagger-ui',
    title: 'Swagger UI Exposed in Production',
    severity: 'medium',
    cvss: 5.3,
    cweId: 'CWE-200',
    description: 'An interactive Swagger UI endpoint is exposed. This can help attackers map and test API operations.',
    remediation: 'Disable interactive API documentation in production or place it behind authentication.',
  },
  {
    path: '/v3/api-docs',
    title: 'API Docs Endpoint Exposed',
    severity: 'medium',
    cvss: 5.3,
    cweId: 'CWE-200',
    description: 'An API documentation endpoint is publicly reachable and discloses endpoint inventory and schemas.',
    remediation: 'Restrict API documentation to authenticated roles only.',
  },
  {
    path: '/actuator/env',
    title: 'Spring Actuator Environment Endpoint Exposed',
    severity: 'high',
    cvss: 8.2,
    cweId: 'CWE-200',
    description: 'The /actuator/env endpoint is exposed and may leak runtime environment variables and secrets.',
    remediation: 'Disable sensitive actuator endpoints or secure them with strong authentication.',
  },
  {
    path: '/actuator/heapdump',
    title: 'Spring Heap Dump Endpoint Exposed',
    severity: 'critical',
    cvss: 9.1,
    cweId: 'CWE-200',
    description: 'A heap dump endpoint is exposed, potentially leaking credentials, tokens, and sensitive in-memory data.',
    remediation: 'Disable heap dump endpoints in production and restrict management interface access.',
  },
  {
    path: '/.well-known/openid-configuration',
    title: 'OIDC Discovery Endpoint Publicly Accessible',
    severity: 'info',
    cvss: 0,
    cweId: 'CWE-200',
    description: 'OIDC metadata endpoint is publicly reachable. This is often expected, but should be reviewed for unnecessary details.',
    remediation: 'Review OIDC metadata exposure and ensure no non-standard sensitive extensions are returned.',
  },
];

const LOGIN_PROBES = ['/api/login', '/auth/login', '/login', '/api/auth/login'];
const GRAPHQL_PROBES = ['/graphql', '/api/graphql'];

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
    module: 'API Security Baseline',
    aiConfidence: opts.aiConfidence || 0.9,
    aiReasoning: opts.aiReasoning || 'Confirmed from API endpoint behavior.',
    evidence: opts.evidence || {},
  };
}

function requestUrl(url, options = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const mod = parsed.protocol === 'https:' ? https : http;
    const method = options.method || 'GET';
    const req = mod.request(
      {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: `${parsed.pathname}${parsed.search}`,
        method,
        timeout: 10000,
        rejectUnauthorized: false,
        headers: options.headers || {},
      },
      (res) => {
        let body = '';
        let collected = 0;
        res.on('data', (chunk) => {
          collected += chunk.length;
          if (collected < 131072) body += chunk;
        });
        res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body }));
      },
    );

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('timeout'));
    });
    req.on('error', reject);

    if (options.body) req.write(options.body);
    req.end();
  });
}

function safeSnippet(body, max = 1200) {
  return String(body || '').replace(/\s+/g, ' ').trim().slice(0, max);
}

export async function scanApi(targetUrl, onFinding, onLog) {
  const findings = [];
  const baseUrl = targetUrl.replace(/\/+$/, '');

  onLog?.('info', `Starting API baseline checks for ${baseUrl}`);

  for (const probe of API_PROBES) {
    const probeUrl = `${baseUrl}${probe.path}`;
    try {
      const res = await requestUrl(probeUrl);
      if (res.statusCode === 200) {
        const finding = makeFinding(
          {
            ...probe,
            aiReasoning: `${probe.path} returned HTTP 200`,
            evidence: {
              type: 'http',
              label: `Endpoint Check ${probe.path}`,
              data: `GET ${probe.path} -> HTTP ${res.statusCode}\n\n${safeSnippet(res.body)}`,
            },
          },
          probeUrl,
        );
        findings.push(finding);
        onFinding?.(finding);
      }
    } catch {
      // Endpoint not reachable or timed out.
    }
  }

  onLog?.('info', 'Checking GraphQL introspection exposure');
  const introspectionPayload = JSON.stringify({
    query: 'query IntrospectionQuery { __schema { queryType { name } mutationType { name } } }',
  });

  for (const path of GRAPHQL_PROBES) {
    const probeUrl = `${baseUrl}${path}`;
    try {
      const res = await requestUrl(probeUrl, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json',
        },
        body: introspectionPayload,
      });

      if (res.statusCode === 200 && /"__schema"\s*:/i.test(res.body)) {
        const finding = makeFinding(
          {
            title: 'GraphQL Introspection Enabled',
            severity: 'medium',
            cvss: 5.3,
            cweId: 'CWE-200',
            description: 'GraphQL introspection appears enabled in a reachable endpoint. This can reveal full schema details to attackers.',
            remediation: 'Disable GraphQL introspection in production or restrict it to trusted authenticated users.',
            aiReasoning: `GraphQL introspection query succeeded on ${path}`,
            evidence: {
              type: 'http',
              label: `GraphQL Probe ${path}`,
              data: `POST ${path} -> HTTP ${res.statusCode}\n\n${safeSnippet(res.body)}`,
            },
          },
          probeUrl,
        );
        findings.push(finding);
        onFinding?.(finding);
        break;
      }
    } catch {
      // Ignore probe errors.
    }
  }

  onLog?.('info', 'Checking dangerous HTTP methods on API surface');
  const methodProbeTargets = ['/', '/api', '/api/v1'];
  const seenMethodFindings = new Set();

  for (const path of methodProbeTargets) {
    const probeUrl = `${baseUrl}${path === '/' ? '' : path}`;
    try {
      const optionsRes = await requestUrl(probeUrl, {
        method: 'OPTIONS',
        headers: { Origin: 'https://attacker.example', 'Access-Control-Request-Method': 'GET' },
      });
      const allowHeader = String(optionsRes.headers.allow || optionsRes.headers['access-control-allow-methods'] || '');
      if (!allowHeader) continue;
      const methods = allowHeader
        .split(',')
        .map((m) => m.trim().toUpperCase())
        .filter(Boolean);
      const dangerous = methods.filter((m) => ['TRACE', 'CONNECT'].includes(m));

      if (dangerous.length > 0) {
        const key = `${probeUrl}:${dangerous.join(',')}`;
        if (seenMethodFindings.has(key)) continue;
        seenMethodFindings.add(key);

        const finding = makeFinding(
          {
            title: `Dangerous HTTP Methods Allowed: ${dangerous.join(', ')}`,
            severity: 'medium',
            cvss: 5.3,
            cweId: 'CWE-16',
            description: `The endpoint exposes dangerous HTTP methods (${dangerous.join(', ')}), increasing abuse risk.`,
            remediation: 'Disable TRACE and CONNECT at web server and application gateway levels.',
            aiReasoning: `Allow/ACAM includes ${dangerous.join(', ')}`,
            evidence: {
              type: 'headers',
              label: `Method Policy ${path}`,
              data: `OPTIONS ${path} -> HTTP ${optionsRes.statusCode}\nAllow: ${allowHeader}`,
            },
          },
          probeUrl,
        );
        findings.push(finding);
        onFinding?.(finding);
      }
    } catch {
      // Ignore method probing failures.
    }
  }

  onLog?.('info', 'Running lightweight API rate-limiting probe');
  let candidate = null;
  let candidateMethod = 'POST';

  for (const path of LOGIN_PROBES) {
    const probeUrl = `${baseUrl}${path}`;
    try {
      const res = await requestUrl(probeUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ username: 'sentinel_probe', password: 'invalid-password' }),
      });

      if (res.statusCode !== 404) {
        candidate = probeUrl;
        candidateMethod = res.statusCode === 405 ? 'GET' : 'POST';
        break;
      }
    } catch {
      // Continue to next candidate.
    }
  }

  if (candidate) {
    const burstSize = Math.max(6, Number(process.env.API_RATE_LIMIT_PROBE_COUNT || 8));
    const requests = Array.from({ length: burstSize }, () =>
      requestUrl(candidate, {
        method: candidateMethod,
        headers: candidateMethod === 'POST'
          ? { 'content-type': 'application/json', accept: 'application/json' }
          : { accept: 'text/html,application/json' },
        body: candidateMethod === 'POST'
          ? JSON.stringify({ username: 'sentinel_probe', password: 'invalid-password' })
          : undefined,
      }).catch(() => ({ statusCode: 0, body: '' })),
    );

    const responses = await Promise.all(requests);
    const statuses = responses.map((r) => r.statusCode).filter((s) => s > 0);
    const has429 = statuses.includes(429);
    const hasRateLimitText = responses.some((r) => /rate\s*limit|too\s*many\s*requests/i.test(r.body || ''));

    if (statuses.length >= Math.ceil(burstSize * 0.7) && !has429 && !hasRateLimitText) {
      const finding = makeFinding(
        {
          title: 'No Apparent Rate Limiting on Authentication Endpoint',
          severity: 'low',
          cvss: 3.7,
          cweId: 'CWE-307',
          description: `A burst of ${burstSize} rapid requests to a likely authentication endpoint did not trigger obvious rate limiting controls.`,
          remediation: 'Implement request throttling and account lockout controls on authentication and sensitive API endpoints.',
          aiReasoning: `Probe endpoint ${new URL(candidate).pathname} returned statuses: ${statuses.join(', ')}`,
          evidence: {
            type: 'http',
            label: 'Rate-Limit Probe',
            data: `${candidateMethod} ${new URL(candidate).pathname} x${burstSize} -> statuses: ${statuses.join(', ')}`,
          },
        },
        candidate,
      );
      findings.push(finding);
      onFinding?.(finding);
    }
  }

  onLog?.('info', `API baseline checks complete - ${findings.length} findings`);
  return findings;
}
