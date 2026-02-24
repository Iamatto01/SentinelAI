import { randomUUID } from 'node:crypto';
import { execSync, spawn } from 'node:child_process';

function isInstalled() {
  try {
    execSync('nuclei --version', { stdio: 'ignore', timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

function makeFinding(opts, targetUrl) {
  return {
    id: `vuln_${randomUUID()}`,
    title: opts.title,
    severity: opts.severity,
    cvss: opts.cvss,
    cweId: opts.cweId || '',
    cveIds: opts.cveIds || [],
    status: 'open',
    asset: opts.asset || targetUrl,
    discovered: new Date().toISOString(),
    description: opts.description,
    remediation: opts.remediation || 'Refer to the CVE/CWE references for remediation guidance.',
    module: 'Vulnerability Scan (nuclei)',
    aiConfidence: opts.aiConfidence || 0.88,
    aiReasoning: opts.aiReasoning || 'Detected by nuclei template scan',
  };
}

const SEVERITY_CVSS = { critical: 9.5, high: 7.5, medium: 5.3, low: 2.5, info: 0 };

export async function scanNuclei(targetUrl, onFinding, onLog) {
  if (!isInstalled()) {
    return { skipped: true, reason: 'nuclei not found on system. Install from https://github.com/projectdiscovery/nuclei/releases' };
  }

  const findings = [];
  onLog?.('info', `Starting nuclei scan on ${targetUrl}`);

  return new Promise((resolve) => {
    const args = [
      '-u', targetUrl,
      '-jsonl',
      '-severity', 'critical,high,medium,low',
      '-rate-limit', '50',
      '-timeout', '10',
      '-silent',
      '-no-color',
    ];

    const child = spawn('nuclei', args, { timeout: 300000 });
    let stderr = '';

    child.stdout.on('data', (data) => {
      const lines = data.toString().split('\n').filter(Boolean);
      for (const line of lines) {
        try {
          const result = JSON.parse(line);
          const severity = (result.info?.severity || 'info').toLowerCase();
          const title = result.info?.name || result['template-id'] || 'Unknown Finding';
          const cveIds = [];
          const refs = result.info?.classification || {};
          if (refs['cve-id']) {
            const cve = Array.isArray(refs['cve-id']) ? refs['cve-id'] : [refs['cve-id']];
            cveIds.push(...cve);
          }
          const cweId = refs['cwe-id']?.[0] || refs['cwe-id'] || '';

          const f = makeFinding({
            title,
            severity,
            cvss: SEVERITY_CVSS[severity] ?? 0,
            cweId: typeof cweId === 'string' ? cweId : '',
            cveIds,
            asset: result['matched-at'] || result.host || targetUrl,
            description: result.info?.description || `Nuclei template "${result['template-id']}" matched against the target.`,
            remediation: result.info?.remediation || '',
            aiConfidence: severity === 'critical' ? 0.95 : severity === 'high' ? 0.90 : 0.85,
            aiReasoning: `Nuclei template: ${result['template-id']}, matcher: ${result['matcher-name'] || 'default'}`,
          }, targetUrl);
          findings.push(f);
          onFinding?.(f);
          onLog?.('info', `nuclei: found ${title} (${severity})`);
        } catch {
          // not valid JSON line
        }
      }
    });

    child.stderr.on('data', (data) => {
      const line = data.toString().trim();
      if (line) {
        stderr += line;
        onLog?.('info', `nuclei: ${line}`);
      }
    });

    child.on('close', (code) => {
      onLog?.('info', `nuclei finished with exit code ${code}`);
      onLog?.('success', `nuclei: found ${findings.length} findings`);
      resolve(findings);
    });

    child.on('error', (err) => {
      onLog?.('error', `nuclei error: ${err.message}`);
      resolve(findings);
    });

    // Safety timeout
    setTimeout(() => {
      try { child.kill(); } catch {}
      onLog?.('warn', 'nuclei: killed after timeout');
      resolve(findings);
    }, 300000);
  });
}
