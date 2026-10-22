/**
 * Beautifies raw scanner output into clean, executive-ready finding titles.
 * Turns strings like:
 *   "nikto: [999100] /: Uncommon header(s) 'speculation-rules' found, with contents: ..."
 * into:
 *   "Uncommon Header Detected: 'speculation-rules'"
 */
export function prettifyTitle(raw) {
  if (!raw) return 'Security Finding'
  let t = String(raw).trim()

  // 1. Semantic pattern matchers for common scanner chatter
  if (/uncommon header\(s\)\s*['"]([^'"]+)['"]/i.test(t)) {
    const m = t.match(/uncommon header\(s\)\s*['"]([^'"]+)['"]/i)
    return `Uncommon Header Detected: '${m[1]}'`
  }
  if (/alt-svc header was found.*advertising HTTP\/3/i.test(t)) {
    return 'HTTP/3 Advertised via Alt-Svc Header'
  }
  if (/anti-clickjacking X-Frame-Options/i.test(t)) {
    return 'Missing Anti-Clickjacking Header (X-Frame-Options)'
  }
  if (/X-Content-Type-Options header is not set/i.test(t)) {
    return 'Missing MIME Sniffing Protection (X-Content-Type-Options)'
  }
  if (/Strict-Transport-Security/i.test(t) && /missing|not set|not present/i.test(t)) {
    return 'Missing Strict-Transport-Security (HSTS) Header'
  }
  if (/Content-Security-Policy/i.test(t) && /missing|not set|not present/i.test(t)) {
    return 'Missing Content-Security-Policy (CSP) Header'
  }
  if (/retrieved x-powered-by header:\s*(.+)/i.test(t)) {
    const m = t.match(/retrieved x-powered-by header:\s*(.+)/i)
    const val = m[1].replace(/[\.;]+$/, '').trim()
    return `Server Technology Banner Disclosure (x-powered-by: ${val})`
  }
  if (/HTML forms discovered\s*—\s*(\d+)\s*injection surfaces?/i.test(t)) {
    const m = t.match(/HTML forms discovered\s*—\s*(\d+)\s*injection surfaces?/i)
    const count = m ? m[1] : '1'
    return `HTML Form Discovered (${count} Injection Surface${count === '1' ? '' : 's'})`
  }
  if (/^open port\s+(\d+)\s*\(([^)]+)\)/i.test(t)) {
    const m = t.match(/^open port\s+(\d+)\s*\(([^)]+)\)/i)
    return `Port ${m[1]}/TCP Open (${m[2].toUpperCase()})`
  }
  if (/Cookie\s+([\w-]+)\s+created without the httponly flag/i.test(t)) {
    const m = t.match(/Cookie\s+([\w-]+)\s+created without the httponly flag/i)
    return `Cookie Missing HttpOnly Flag (${m[1]})`
  }
  if (/Cookie\s+([\w-]+)\s+created without the secure flag/i.test(t)) {
    const m = t.match(/Cookie\s+([\w-]+)\s+created without the secure flag/i)
    return `Cookie Missing Secure Flag (${m[1]})`
  }
  if (/cve-(\d{4})-(\d+)/i.test(t) && !/^\s*CVE-/i.test(t)) {
    // If it mentions a CVE, ensure CVE is prominently featured
    const cve = t.match(/CVE-\d{4}-\d+/i)?.[0]
    // Clean remaining text
    let clean = t.replace(/^(?:nikto|nuclei|nmap|katana|httpx|arjun|ffuf)\s*:\s*/i, '')
                 .replace(/\[\w+\]\s*/g, '')
                 .replace(new RegExp(cve, 'gi'), '')
                 .trim()
    return `${clean ? clean + ' ' : ''}(${cve.toUpperCase()})`.trim()
  }

  // 2. Generic prefix stripping
  t = t.replace(/^(?:nikto|nuclei|nmap|httpx|katana|dalfox|ffuf|subfinder|sqlmap|wpscan|arjun|native:[\w-]+|custom:[\w-]+)\s*:\s*/i, '')
  t = t.replace(/^\[(?:\d+|[+*✓x!~]|info|low|medium|high|critical)\]\s*/gi, '')
  t = t.replace(/^\/?[:\-]\s*/, '')
  t = t.replace(/^\[(?:\d+|[+*✓x!~])\]\s*/gi, '')
  t = t.replace(/^\/?[:\-]\s*/, '')
  t = t.replace(/^Target:\s*https?:\/\/\S+\s*[-–—]\s*/i, '')

  // 3. Clean trailing periods and extra spaces
  t = t.replace(/[\.\s]+$/, '').replace(/\s{2,}/g, ' ').trim()

  // 4. Capitalize first letter
  if (t.length > 0) {
    t = t.charAt(0).toUpperCase() + t.slice(1)
  }

  return t || 'Security Finding'
}
