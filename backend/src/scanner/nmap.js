import { randomUUID } from 'node:crypto';
import { execSync, spawn } from 'node:child_process';

function isInstalled() {
  try {
    execSync('nmap --version', { stdio: 'ignore', timeout: 5000 });
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
    cweId: opts.cweId || 'CWE-200',
    cveIds: opts.cveIds || [],
    status: 'open',
    asset: targetUrl,
    discovered: new Date().toISOString(),
    description: opts.description,
    remediation: opts.remediation,
    module: 'Port Scanning (nmap)',
    aiConfidence: opts.aiConfidence || 0.90,
    aiReasoning: opts.aiReasoning || 'Detected by nmap port scan',
  };
}

const HIGH_RISK_PORTS = {
  21: { name: 'FTP', severity: 'high', cvss: 7.5, desc: 'FTP allows unencrypted file transfer and often supports anonymous access.' },
  23: { name: 'Telnet', severity: 'high', cvss: 8.1, desc: 'Telnet transmits all data including credentials in cleartext.' },
  25: { name: 'SMTP', severity: 'medium', cvss: 5.3, desc: 'Open SMTP relay may allow spam and phishing campaigns.' },
  445: { name: 'SMB', severity: 'high', cvss: 8.1, desc: 'SMB is frequently targeted by ransomware and worms (e.g., WannaCry).' },
  3389: { name: 'RDP', severity: 'high', cvss: 8.1, desc: 'Externally exposed RDP is a prime target for brute-force attacks.' },
  5900: { name: 'VNC', severity: 'high', cvss: 7.5, desc: 'VNC often lacks strong authentication and may expose the desktop.' },
  27017: { name: 'MongoDB', severity: 'high', cvss: 9.1, desc: 'Exposed MongoDB may allow unauthenticated database access.' },
  6379: { name: 'Redis', severity: 'high', cvss: 9.1, desc: 'Exposed Redis often has no authentication and allows arbitrary data access.' },
  3306: { name: 'MySQL', severity: 'medium', cvss: 6.5, desc: 'Externally exposed MySQL database server.' },
  5432: { name: 'PostgreSQL', severity: 'medium', cvss: 6.5, desc: 'Externally exposed PostgreSQL database server.' },
};

export async function scanNmap(targetUrl, onFinding, onLog) {
  if (!isInstalled()) {
    return { skipped: true, reason: 'nmap not found on system. Install from https://nmap.org/download.html' };
  }

  const findings = [];
  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return { skipped: true, reason: 'Invalid target URL' };
  }

  const hostname = parsed.hostname;
  onLog?.('info', `Starting nmap scan on ${hostname}`);

  return new Promise((resolve) => {
    const args = [
      '-sT',                // TCP connect scan (no root needed)
      '-sV',                // Service version detection
      '-T4',                // Aggressive timing
      '--top-ports', '100', // Top 100 ports
      '--open',             // Only show open ports
      '-oX', '-',           // XML output to stdout
      hostname,
    ];

    const child = spawn('nmap', args, { timeout: 120000 });
    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    child.stderr.on('data', (data) => {
      const line = data.toString().trim();
      if (line) {
        stderr += line;
        onLog?.('info', `nmap: ${line}`);
      }
    });

    child.on('close', (code) => {
      onLog?.('info', `nmap finished with exit code ${code}`);

      // Parse XML output using regex (avoiding xml2js dependency for simplicity)
      const portRegex = /<port protocol="([^"]*)" portid="(\d+)">[\s\S]*?<state state="([^"]*)"[^>]*\/>[\s\S]*?<service name="([^"]*)"(?:\s+product="([^"]*)")?(?:\s+version="([^"]*)")?/g;
      let match;
      while ((match = portRegex.exec(stdout)) !== null) {
        const [, protocol, portid, state, serviceName, product, version] = match;
        const port = parseInt(portid);

        if (state !== 'open') continue;

        const serviceStr = [product, version].filter(Boolean).join(' ') || serviceName;
        const highRisk = HIGH_RISK_PORTS[port];

        if (highRisk) {
          const f = makeFinding({
            title: `Open ${highRisk.name} Port (${port}/${protocol})`,
            severity: highRisk.severity,
            cvss: highRisk.cvss,
            cweId: 'CWE-200',
            description: `Port ${port} (${highRisk.name}) is open and running ${serviceStr}. ${highRisk.desc}`,
            remediation: `Close port ${port} if not needed, or restrict access via firewall rules. Use an encrypted alternative if available.`,
            aiReasoning: `nmap detected open port ${port}: ${serviceStr}`,
          }, targetUrl);
          findings.push(f);
          onFinding?.(f);
        } else {
          const f = makeFinding({
            title: `Open Port: ${port}/${protocol} (${serviceName})`,
            severity: 'info',
            cvss: 0,
            cweId: 'CWE-200',
            description: `Port ${port} is open and running ${serviceStr}.`,
            remediation: `Review whether port ${port} needs to be publicly accessible. Close unnecessary ports.`,
            aiConfidence: 0.85,
            aiReasoning: `nmap detected open port ${port}: ${serviceStr}`,
          }, targetUrl);
          findings.push(f);
          onFinding?.(f);
        }
      }

      onLog?.('success', `nmap: found ${findings.length} findings`);
      resolve(findings);
    });

    child.on('error', (err) => {
      onLog?.('error', `nmap error: ${err.message}`);
      resolve(findings);
    });

    // Safety timeout
    setTimeout(() => {
      try { child.kill(); } catch {}
      onLog?.('warn', 'nmap: killed after timeout');
      resolve(findings);
    }, 120000);
  });
}
