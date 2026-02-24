import { randomUUID } from 'node:crypto';
import dns from 'node:dns/promises';

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
    module: 'Subdomain Enumeration',
    aiConfidence: opts.aiConfidence || 0.85,
    aiReasoning: opts.aiReasoning || 'Discovered via DNS resolution brute-force',
    evidence: opts.evidence || {},
  };
}

const COMMON_SUBDOMAINS = [
  'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging', 'test',
  'beta', 'portal', 'app', 'blog', 'shop', 'store', 'cdn', 'media',
  'static', 'assets', 'img', 'images', 'ns1', 'ns2', 'mx', 'smtp',
  'pop', 'imap', 'webmail', 'cpanel', 'whm', 'vpn', 'remote',
  'git', 'gitlab', 'jenkins', 'ci', 'jira', 'confluence', 'wiki',
  'docs', 'support', 'help', 'status', 'monitor', 'grafana',
  'dashboard', 'internal', 'intranet', 'backup', 'old', 'new',
  'demo', 'sandbox', 'uat', 'qa', 'preprod', 'prod', 'db',
  'database', 'redis', 'elastic', 'kibana', 'kafka', 'rabbit',
  'mq', 'queue', 'auth', 'sso', 'login', 'oauth', 'api-v2',
  'graphql', 'rest', 'ws', 'socket', 'realtime', 'push',
  'm', 'mobile', 'android', 'ios', 'download', 'upload',
  'files', 'cloud', 'aws', 'azure', 'gcp', 's3',
];

async function resolveSubdomain(hostname) {
  try {
    const addresses = await dns.resolve4(hostname);
    return { hostname, addresses, found: true };
  } catch {
    return { hostname, found: false };
  }
}

export async function scanSubdomains(targetUrl, onFinding, onLog) {
  const findings = [];

  const parsed = new URL(targetUrl);
  const baseDomain = parsed.hostname;

  // Skip if target is an IP address
  if (/^\d+\.\d+\.\d+\.\d+$/.test(baseDomain)) {
    onLog?.('info', 'Skipping subdomain enumeration for IP address targets');
    return findings;
  }

  onLog?.('info', `Starting subdomain enumeration for ${baseDomain}`);
  onLog?.('info', `Testing ${COMMON_SUBDOMAINS.length} common subdomain prefixes`);

  const resolved = [];
  const sensitive = [];

  // Resolve in batches of 10 to avoid overwhelming DNS
  for (let i = 0; i < COMMON_SUBDOMAINS.length; i += 10) {
    const batch = COMMON_SUBDOMAINS.slice(i, i + 10);
    const promises = batch.map((sub) => {
      const hostname = `${sub}.${baseDomain}`;
      return resolveSubdomain(hostname);
    });
    const results = await Promise.all(promises);
    for (const r of results) {
      if (r.found) {
        resolved.push(r);
        // Check if it's a sensitive/development subdomain
        const prefix = r.hostname.split('.')[0];
        const sensitiveNames = [
          'admin', 'dev', 'staging', 'test', 'beta', 'internal', 'intranet',
          'backup', 'old', 'demo', 'sandbox', 'uat', 'qa', 'preprod',
          'git', 'gitlab', 'jenkins', 'ci', 'jira', 'cpanel', 'whm',
          'vpn', 'remote', 'db', 'database', 'redis', 'elastic', 'kibana',
          'grafana', 'monitor', 'dashboard',
        ];
        if (sensitiveNames.includes(prefix)) {
          sensitive.push(r);
        }
      }
    }
  }

  onLog?.('info', `Found ${resolved.length} active subdomains out of ${COMMON_SUBDOMAINS.length} tested`);

  if (resolved.length === 0) {
    onLog?.('info', 'No subdomains discovered');
    return findings;
  }

  // Build evidence
  const evidenceLines = resolved.map((r) => `${r.hostname} -> ${r.addresses.join(', ')}`);

  // Main finding: subdomain enumeration summary
  const f = makeFinding({
    title: `${resolved.length} Active Subdomains Discovered on ${baseDomain}`,
    severity: 'info',
    cvss: 0,
    description: `Subdomain enumeration discovered ${resolved.length} active subdomains for ${baseDomain}. A large attack surface increases exposure to potential vulnerabilities across different services.`,
    remediation: 'Review all active subdomains and decommission unused ones. Ensure development and staging environments are not publicly accessible.',
    aiReasoning: `DNS brute-force resolved ${resolved.length}/${COMMON_SUBDOMAINS.length} subdomain prefixes`,
    evidence: { type: 'dns', label: 'Discovered Subdomains', data: evidenceLines.join('\n') },
  }, targetUrl);
  findings.push(f);
  onFinding?.(f);

  // Finding for sensitive/development subdomains
  if (sensitive.length > 0) {
    const sensLines = sensitive.map((r) => `${r.hostname} -> ${r.addresses.join(', ')}`);
    const f2 = makeFinding({
      title: `${sensitive.length} Sensitive Subdomains Exposed: ${sensitive.slice(0, 3).map((r) => r.hostname.split('.')[0]).join(', ')}`,
      severity: 'medium',
      cvss: 5.3,
      cweId: 'CWE-200',
      description: `Found ${sensitive.length} sensitive subdomains (development, admin, internal) that are publicly resolvable. These often have weaker security controls and may expose internal tools or data.`,
      remediation: 'Restrict access to development, staging, admin, and internal subdomains using VPN, IP whitelisting, or remove their public DNS records entirely.',
      aiReasoning: `Sensitive subdomains found: ${sensitive.map((r) => r.hostname.split('.')[0]).join(', ')}`,
      evidence: { type: 'dns', label: 'Sensitive Subdomains', data: sensLines.join('\n') },
    }, targetUrl);
    findings.push(f2);
    onFinding?.(f2);
  }

  // Check for subdomain pointing to different IPs (potential takeover surface)
  const uniqueIps = new Set();
  for (const r of resolved) {
    for (const addr of r.addresses) uniqueIps.add(addr);
  }
  if (uniqueIps.size > 5) {
    const ipList = Array.from(uniqueIps).slice(0, 20).join(', ');
    const f3 = makeFinding({
      title: `Large IP Spread: ${uniqueIps.size} Unique IPs Across Subdomains`,
      severity: 'low',
      cvss: 2.0,
      description: `Subdomains resolve to ${uniqueIps.size} different IP addresses, indicating a distributed infrastructure. Each IP is a potential entry point that needs independent security review.`,
      remediation: 'Ensure all servers hosting subdomains are patched and hardened. Consider consolidating services where possible.',
      aiReasoning: `${uniqueIps.size} unique IPs detected across ${resolved.length} subdomains`,
      evidence: { type: 'dns', label: 'IP Address Distribution', data: `Unique IPs (${uniqueIps.size}):\n${ipList}` },
    }, targetUrl);
    findings.push(f3);
    onFinding?.(f3);
  }

  onLog?.('info', `Subdomain enumeration complete - ${findings.length} findings`);
  return findings;
}
