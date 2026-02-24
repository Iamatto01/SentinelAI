import { randomUUID } from 'node:crypto';
import tls from 'node:tls';
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
    module: 'SSL/TLS Analysis',
    aiConfidence: opts.aiConfidence || 0.95,
    aiReasoning: opts.aiReasoning || 'Confirmed from TLS handshake analysis',
    evidence: opts.evidence || {},
  };
}

function tlsConnect(hostname, port, options = {}) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host: hostname, port, rejectUnauthorized: false, timeout: 10000, ...options }, () => {
      const cert = socket.getPeerCertificate();
      const protocol = socket.getProtocol();
      const cipher = socket.getCipher();
      const authorized = socket.authorized;
      socket.end();
      resolve({ cert, protocol, cipher, authorized });
    });
    socket.on('timeout', () => { socket.destroy(); reject(new Error('TLS connection timed out')); });
    socket.on('error', reject);
  });
}

function httpProbe(hostname, port) {
  return new Promise((resolve, reject) => {
    const req = http.get({ hostname, port, path: '/', timeout: 5000 }, (res) => {
      res.resume();
      resolve(true);
    });
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
  });
}

export async function scanSsl(targetUrl, onFinding, onLog) {
  const findings = [];
  let parsed;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return findings;
  }

  const hostname = parsed.hostname;
  const isHttps = parsed.protocol === 'https:';
  const port = parsed.port ? parseInt(parsed.port) : (isHttps ? 443 : 80);

  onLog?.('info', `Analysing TLS configuration for ${hostname}:${port}`);

  // Check if plain HTTP
  if (!isHttps) {
    onLog?.('warn', 'Target uses plain HTTP - no TLS encryption');
    // Check if HTTP is used (no encryption)
    const f = makeFinding({
      title: 'Site Accessible Over Unencrypted HTTP',
      severity: 'high',
      cvss: 7.5,
      cweId: 'CWE-319',
      description: `The target ${targetUrl} is accessed over plain HTTP without encryption. All data transmitted, including credentials and session tokens, can be intercepted.`,
      remediation: 'Configure the server to use HTTPS with a valid TLS certificate. Redirect all HTTP traffic to HTTPS.',
      aiReasoning: 'Target URL uses http:// scheme',
    }, targetUrl);
    findings.push(f);
    onFinding?.(f);

    // Try if HTTPS is available on 443
    onLog?.('info', 'Checking if HTTPS is available on port 443');
    try {
      await tlsConnect(hostname, 443);
      const f2 = makeFinding({
        title: 'HTTPS Available But Not Enforced',
        severity: 'medium',
        cvss: 5.3,
        cweId: 'CWE-319',
        description: 'HTTPS is available on port 443, but the site is being accessed over HTTP. Users may accidentally use the unencrypted version.',
        remediation: 'Implement HTTP-to-HTTPS redirect and set the HSTS header.',
        aiReasoning: 'TLS handshake succeeded on port 443 while target uses HTTP',
      }, targetUrl);
      findings.push(f2);
      onFinding?.(f2);
    } catch {
      // HTTPS not available
    }

    return findings;
  }

  // HTTPS target - perform TLS analysis
  onLog?.('info', `Performing TLS handshake with ${hostname}:${port}`);
  let tlsInfo;
  try {
    tlsInfo = await tlsConnect(hostname, port);
  } catch (err) {
    const f = makeFinding({
      title: 'TLS Connection Failed',
      severity: 'high',
      cvss: 7.5,
      cweId: 'CWE-295',
      description: `Could not establish a TLS connection to ${hostname}:${port}: ${err.message}`,
      remediation: 'Ensure the server has a properly configured TLS certificate and supports modern TLS protocols.',
      aiReasoning: `TLS error: ${err.message}`,
    }, targetUrl);
    findings.push(f);
    onFinding?.(f);
    return findings;
  }

  const { cert, protocol, cipher, authorized } = tlsInfo;

  // Build certificate evidence summary
  const certEvidence = [
    `Protocol: ${protocol || 'unknown'}`,
    `Cipher: ${cipher?.name || 'unknown'}`,
    `Authorized: ${authorized}`,
    cert?.subject ? `Subject: CN=${cert.subject.CN || ''}, O=${cert.subject.O || ''}` : '',
    cert?.issuer ? `Issuer: CN=${cert.issuer.CN || ''}, O=${cert.issuer.O || ''}` : '',
    cert?.valid_from ? `Valid From: ${cert.valid_from}` : '',
    cert?.valid_to ? `Valid To: ${cert.valid_to}` : '',
    cert?.serialNumber ? `Serial: ${cert.serialNumber}` : '',
    cert?.fingerprint256 ? `SHA-256: ${cert.fingerprint256}` : '',
  ].filter(Boolean).join('\n');

  onLog?.('info', `TLS handshake successful - protocol: ${protocol || 'unknown'}, cipher: ${cipher?.name || 'unknown'}, cert authorised: ${authorized}`);

  // Self-signed or untrusted certificate
  onLog?.('info', 'Checking certificate trust chain');
  if (!authorized && cert) {
    const issuer = cert.issuer?.O || cert.issuer?.CN || 'Unknown';
    const subject = cert.subject?.O || cert.subject?.CN || 'Unknown';
    const isSelfSigned = issuer === subject;
    const f = makeFinding({
      title: isSelfSigned ? 'Self-Signed TLS Certificate' : 'Untrusted TLS Certificate',
      severity: 'high',
      cvss: 7.5,
      cweId: 'CWE-295',
      description: isSelfSigned
        ? `The certificate is self-signed (issuer: ${issuer}). Browsers will show security warnings and MITM attacks become trivial.`
        : `The certificate issued by "${issuer}" is not trusted by the system certificate store.`,
      remediation: 'Obtain a certificate from a trusted Certificate Authority (e.g., Let\'s Encrypt).',
      aiReasoning: `Certificate authorized: false, issuer: ${issuer}, subject: ${subject}`,
      evidence: { type: 'certificate', label: 'TLS Certificate Details', data: certEvidence },
    }, targetUrl);
    findings.push(f);
    onFinding?.(f);
  }

  // Certificate expiry
  onLog?.('info', 'Checking certificate expiry date');
  if (cert?.valid_to) {
    const expiry = new Date(cert.valid_to);
    const now = new Date();
    const daysLeft = Math.floor((expiry - now) / 86400000);
    if (daysLeft < 0) {
      const f = makeFinding({
        title: 'TLS Certificate Has Expired',
        severity: 'high',
        cvss: 7.5,
        cweId: 'CWE-295',
        description: `The certificate expired on ${cert.valid_to} (${Math.abs(daysLeft)} days ago). Browsers will block access to this site.`,
        remediation: 'Renew the TLS certificate immediately.',
        aiConfidence: 1.0,
        aiReasoning: `Certificate valid_to: ${cert.valid_to}`,
        evidence: { type: 'certificate', label: 'TLS Certificate Details', data: certEvidence },
      }, targetUrl);
      findings.push(f);
      onFinding?.(f);
    } else if (daysLeft < 30) {
      const f = makeFinding({
        title: 'TLS Certificate Expiring Soon',
        severity: 'medium',
        cvss: 4.3,
        cweId: 'CWE-295',
        description: `The certificate expires on ${cert.valid_to} (${daysLeft} days remaining). Plan for renewal to avoid service disruption.`,
        remediation: 'Renew the TLS certificate before expiry. Consider using auto-renewal with Let\'s Encrypt.',
        aiReasoning: `Certificate expires in ${daysLeft} days`,
        evidence: { type: 'certificate', label: 'TLS Certificate Details', data: certEvidence },
      }, targetUrl);
      findings.push(f);
      onFinding?.(f);
    }
  }

  // Deprecated TLS versions
  onLog?.('info', `Checking TLS protocol version: ${protocol || 'unknown'}`);
  if (protocol) {
    const deprecated = ['TLSv1', 'TLSv1.1', 'SSLv3'];
    if (deprecated.some((d) => protocol.includes(d))) {
      const f = makeFinding({
        title: `Deprecated TLS Protocol Version: ${protocol}`,
        severity: 'medium',
        cvss: 5.9,
        cweId: 'CWE-326',
        cveIds: ['CVE-2011-3389', 'CVE-2014-3566'],
        description: `The server negotiated ${protocol}, which is deprecated and vulnerable to known attacks (BEAST, POODLE).`,
        remediation: 'Disable TLSv1.0, TLSv1.1, and SSLv3. Only allow TLSv1.2 and TLSv1.3.',
        aiReasoning: `Negotiated protocol: ${protocol}`,
        evidence: { type: 'certificate', label: 'TLS Protocol Info', data: `Protocol: ${protocol}\nCipher: ${cipher?.name || 'unknown'}` },
      }, targetUrl);
      findings.push(f);
      onFinding?.(f);
    }
  }

  // Weak cipher suites
  onLog?.('info', `Checking cipher suite strength: ${cipher?.name || 'unknown'}`);
  if (cipher?.name) {
    const weak = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'MD5'];
    const matched = weak.filter((w) => cipher.name.toUpperCase().includes(w));
    if (matched.length > 0) {
      const f = makeFinding({
        title: `Weak Cipher Suite: ${cipher.name}`,
        severity: 'medium',
        cvss: 5.3,
        cweId: 'CWE-326',
        description: `The server uses a weak cipher suite "${cipher.name}" which contains: ${matched.join(', ')}. These are cryptographically weak.`,
        remediation: 'Configure the server to use only strong cipher suites (AES-GCM, ChaCha20-Poly1305).',
        aiReasoning: `Cipher: ${cipher.name}, version: ${cipher.version}`,
        evidence: { type: 'certificate', label: 'Cipher Suite', data: `Cipher: ${cipher.name}\nVersion: ${cipher.version}\nWeak components: ${matched.join(', ')}` },
      }, targetUrl);
      findings.push(f);
      onFinding?.(f);
    }
  }

  onLog?.('info', `SSL/TLS analysis complete - ${findings.length} issues found`);
  return findings;
}
