import { spawn } from 'node:child_process'
import fs from 'node:fs'

/**
 * Native tool runner — executes security tools directly via child_process.
 * This is the PRIMARY execution engine for all blackbox scanning (the
 * hexstrike HTTP middle-layer was removed: backend → subprocess directly,
 * no network hop, live stdout capture, tuned flags per tool).
 *
 * Only used when backend runs on the same machine as the tools (Kali all-in-one).
 */

const TIMEOUT_MS = 600000

/** Check if a binary exists in PATH. */
async function which(bin) {
  return new Promise((resolve) => {
    const proc = spawn('which', [bin])
    proc.on('close', (code) => resolve(code === 0))
    proc.on('error', () => resolve(false))
  })
}

/** Expand simple glob dirs (e.g. /usr/lib/ruby/gems/STAR/bin) into existing paths. */
function expandGlobDirs(patterns) {
  const out = []
  for (const p of patterns) {
    if (!p.includes('*')) { out.push(p); continue }
    const parent = p.slice(0, p.indexOf('/*'))
    try {
      for (const d of fs.readdirSync(parent)) {
        const full = `${parent}/${d}/bin`
        if (fs.existsSync(full)) out.push(full)
      }
    } catch { /* parent missing — skip */ }
  }
  return out
}

/** Run a command, capture stdout/stderr, respect timeout. */
async function run(cmd, args, { timeout = TIMEOUT_MS } = {}) {
  return new Promise((resolve) => {
    // Ensure Go/Python gem tool paths are reachable regardless of caller env
    const extra = expandGlobDirs([
      '/usr/local/bin', '/usr/local/sbin',
      '/root/go/bin', '/root/.local/bin',
      '/usr/lib/ruby/gems/*/bin', '/var/lib/gems/*/bin',
      process.env.HOME ? `${process.env.HOME}/go/bin` : null,
      process.env.HOME ? `${process.env.HOME}/.local/bin` : null,
    ].filter(Boolean)).join(':')
    const env = { ...process.env, PATH: `${process.env.PATH || ''}:${extra}` }
    // No shell:true — args are arrays, so metacharacters in user-supplied
    // targets can't be interpreted by a shell (command-injection fix).
    // detached + process-group kill so grandchildren (real scanners spawned
    // via wrappers) don't survive as orphans when we time out.
    const proc = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], env, detached: true })
    let stdout = ''
    let stderr = ''
    const killTree = () => {
      try { process.kill(-proc.pid, 'SIGKILL') } catch { try { proc.kill('SIGKILL') } catch { /* already gone */ } }
    }
    const timer = setTimeout(() => {
      killTree()
      resolve({ success: false, timedOut: true, stdout, stderr, error: `timeout after ${timeout}ms` })
    }, timeout)

    proc.stdout.on('data', (d) => { stdout += d.toString() })
    proc.stderr.on('data', (d) => { stderr += d.toString() })
    proc.on('close', (code) => {
      clearTimeout(timer)
      // Surface non-zero exit with stderr snippet for debugging
      const stderrSnippet = stderr.trim().split('\n').slice(-3).join(' | ')
      resolve({
        success: code === 0,
        code,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        error: code !== 0 ? `exit code ${code}${stderrSnippet ? ` — ${stderrSnippet}` : ''}` : null,
      })
    })
    proc.on('error', (err) => {
      clearTimeout(timer)
      resolve({ success: false, error: err.message, stdout: stdout.trim(), stderr: stderr.trim() })
    })
  })
}

/** Normalizers — same as hexstrike.js but kept here so this module is standalone. */
const toUrl = (t) => /^https?:\/\//i.test(t) ? t : `https://${t}`
const toHost = (t) => {
  try { return new URL(toUrl(t)).hostname } catch { return t.replace(/^https?:\/\//i, '').split('/')[0] }
}

/** Extract the registrable root domain, respecting second-level TLDs (edu.my, co.uk, etc.). */
const SECOND_LEVEL_TLDS = new Set([
  'edu.my', 'com.my', 'net.my', 'org.my', 'gov.my', 'mil.my', 'sch.my',
  'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'sch.uk', 'ac.uk', 'gov.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz',
  'co.id', 'web.id', 'ac.id', 'go.id', 'my.id', 'sch.id',
  'co.jp', 'ne.jp', 'or.jp', 'go.jp', 'ac.jp',
  'com.sg', 'edu.sg', 'gov.sg', 'net.sg', 'org.sg',
  'com.hk', 'edu.hk', 'gov.hk', 'net.hk', 'org.hk',
  'co.za', 'gov.za', 'ac.za', 'edu.za',
  'com.br', 'gov.br', 'edu.br', 'org.br',
  'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in',
  'edu.cn', 'gov.cn', 'com.cn', 'net.cn', 'org.cn',
])
const toRootDomain = (t) => {
  const host = toHost(t).toLowerCase().trim()
  const parts = host.split('.').filter(Boolean)
  if (parts.length <= 2) return parts.join('.')
  const lastTwo = parts.slice(-2).join('.')
  if (SECOND_LEVEL_TLDS.has(lastTwo)) return parts.slice(-3).join('.')
  return parts.slice(-2).join('.')
}

/**
 * Native tool definitions: binary name, argument builder, and whether we need
 * to strip the scheme (host tools) or keep it (URL tools).
 */
export const NATIVE_TOOLS = {
  subfinder: {
    bin: 'subfinder',
    args: (t) => ['-d', toRootDomain(t), '-silent'],
    desc: 'Subdomain enumeration',
  },
  amass: {
    // Passive-only enum (no DNS queries to target) — fast + safe, complements subfinder
    bin: 'amass',
    altBins: ['amass.net', 'amass_linux_amd64'],
    args: (t) => ['enum', '-passive', '-d', toRootDomain(t), '-timeout', '4'],
    timeout: 300000,
    desc: 'OSINT subdomain mapping (passive)',
  },
  // Active DNS brute-force — finds subdomains passive sources miss (aziz., dev., staging.)
  // Primary: gobuster dns. Falls back to dnsrecon if gobuster's -d parser rejects
  // the domain (known gobuster v3.0 bug with hyphenated domains like "myces-fms.com").
  dnsbrute: {
    bin: 'gobuster',
    fallbackDef: 'dnsrecon',  // runNativeTool will try this if gobuster fails
    args: (t) => {
      const bare = toRootDomain(t)
      return ['dns', '-d', bare, '-w', '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt', '-q', '-t', '30', '--timeout', '10s']
    },
    // Simpler invocation for older gobuster builds that reject --timeout.
    altArgs: (t) => {
      const bare = toRootDomain(t)
      return ['dns', '-d', bare, '-w', '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt', '-q']
    },
    desc: 'Subdomain brute-force',
  },
  // dnsrecon fallback — invoked when gobuster's -d flag rejects the domain.
  // Uses its own wordlist; -D for subdomain brute, -t std.
  dnsrecon: {
    bin: 'dnsrecon',
    args: (t) => {
      const bare = toRootDomain(t)
      return ['-d', bare, '-D', '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt', '-t', 'brt', '--threads', '30']
    },
    desc: 'DNS enumeration (dnsrecon)',
  },
  gobuster: {
    bin: 'gobuster',
    args: (t) => ['dir', '-u', toUrl(t), '-w', '/usr/share/seclists/Discovery/Web-Content/common.txt', '-q', '-s', '200,204,301,302,307,401,403'],
    desc: 'Directory brute-force',
  },
  // httpx: support BOTH ProjectDiscovery (Go) and Python httpx CLI.
  // Try Go-style args first; if the binary rejects them (Python httpx), the
  // caller falls back to plain probe via `altArgs` (see runNativeTool).
  httpx: {
    bin: 'httpx',
    altBins: ['httpx-toolkit', 'httpx-pd'],
    args: (t) => [toUrl(t), '-status-code', '-title', '-tech-detect', '-silent', '-json'],
    altArgs: (t) => [toUrl(t)],
    desc: 'HTTP probing',
  },
  katana: {
    // katana v1.7 hangs with -u on some targets (Cloudflare-fronted sites);
    // stdin mode works reliably. -ct caps crawl duration, -iqp skips
    // duplicate query-param URLs (Moodle generates thousands).
    bin: 'bash',
    args: (t) => ['-c', `echo ${JSON.stringify(toUrl(t))} | katana -silent -d 2 -ct 90 -c 20 -iqp`],
    // Older katana builds: classic -u invocation.
    altArgs: (t) => ['-u', toUrl(t), '-silent', '-d', '2'],
    timeout: 150000,
    desc: 'Web crawling',
  },
  dalfox: {
    bin: 'dalfox',
    // Probe base URL with common test parameters when no discovered URLs exist.
    // --skip-mining-all reduces noise; --waf-evasion increases hit rate.
    args: (t) => {
      const u = toUrl(t)
      const probeUrl = u.includes('?') ? u : `${u}${u.endsWith('/') ? '' : '/'}?q=test&search=test&id=1&query=test`
      return ['url', probeUrl, '--silence', '--format', 'json', '--skip-mining-all', '--timeout', '30']
    },
    // Older dalfox builds don't support --skip-mining-all; use minimal flags.
    altArgs: (t) => {
      const u = toUrl(t)
      return ['url', u, '--silence', '--timeout', '30']
    },
      timeout: 180000, // 3 min — dalfox on a single URL should finish well under this
      desc: 'XSS scanning',
    },
  wpscan: {
    bin: 'wpscan',
    args: (t) => ['--url', toUrl(t), '--no-banner', '--format', 'json'],
    altArgs: (t) => ['--url', toUrl(t), '--no-banner'],
    desc: 'WordPress scanning',
  },
  sqlmap: {
    bin: 'sqlmap',
    args: (t) => ['-u', toUrl(t), '--batch', '--level=1', '--risk=1', '--smart', '--disable-coloring'],
      timeout: 240000, // 4 min — sqlmap --batch --level=1 on a single URL should finish under this
      desc: 'SQL injection testing',
    },
  arjun: {
    // arjun buffers stdout when run via the easy-install wrapper — run as an
    // unbuffered python module so output streams live. GET-only + tuned
    // threads keeps a large app (Moodle) within the 5-minute budget.
    bin: 'python3',
    args: (t) => ['-u', '-m', 'arjun', '-u', toUrl(t), '-m', 'GET', '-t', '10', '-c', '20', '-T', '10', '--stable'],
    // Fallback: classic wrapper invocation (older installs).
    altArgs: (t) => ['-u', toUrl(t), '--stable', '-c', '30', '-t', '3'],
    parameterDiscovery: true,
    timeout: 300000,
    desc: 'HTTP parameter discovery',
  },
  nmap: {
    bin: 'nmap',
    args: (t) => ['-sCV', '-T4', '-Pn', toHost(t)],
    desc: 'Port scanning',
  },
  nikto: {
    bin: 'nikto',
    args: (t) => ['-h', toHost(t), '-maxtime', '240', '-Tuning', 'x6'],
    // Nikto is notoriously slow (10+ min on hardened hosts). Cap at 4 minutes
    // and skip intrusive tests (Tuning x6 = interesting files + misconfig only).
    timeout: 240000,
    desc: 'Web server scanning',
  },
  nuclei: {
    bin: 'nuclei',
    // nuclei v3 renamed -json to -j (jsonl) and dropped -no-mh.
    args: (t) => ['-u', toUrl(t), '-silent', '-j', '-timeout', '30', '-rate-limit', '150'],
    // Older nuclei v2 builds use -json and reject -j; retry with minimal flags.
    altArgs: (t) => ['-u', toUrl(t), '-silent', '-json'],
    desc: 'Template-based scanning',
  },
  ffuf: {
    bin: 'ffuf',
    args: (t) => ['-u', `${toUrl(t)}/FUZZ`, '-w', '/usr/share/seclists/Discovery/Web-Content/common.txt', '-mc', '200,204,301,302,307,401,403', '-s'],
    desc: 'Directory fuzzing',
  },
  whatweb: {
    bin: 'whatweb',
    args: (t) => [toUrl(t), '--color=never', '-a', '3'],
    desc: 'Web technology fingerprinting',
  },
  wafw00f: {
    bin: 'wafw00f',
    args: (t) => [toUrl(t)],
    desc: 'WAF detection',
  },
  // Ad-hoc nmap NSE script runs — target string carries full args: "host --script X -p Y"
    // Short timeout: NSE scripts against filtered ports (common behind Cloudflare/WAF)
    // will otherwise hang for the full 600s default × 5 scripts = 50 min of dead time.
    'nmap-script': {
      bin: 'nmap',
      args: (t) => t.split(' ').filter(Boolean),
      desc: 'Nmap NSE script probe',
      timeout: 120000, // 2 min — enough for a single NSE script on a live host
    },
  // Interactive console — run arbitrary commands (e.g., telnet, nc, curl, hydra, msfconsole)
  console: {
    bin: 'bash',
    args: (t) => ['-c', t],
    desc: 'Arbitrary command execution',
    timeout: 120000, // 2 min default — customizable per invocation
  },

  // ─────────────────────────────────────────────────────────────────
  // EXPANDED REGISTRY — deep content discovery, TLS audit, OSINT
  // ─────────────────────────────────────────────────────────────────

  // Recursive directory fuzzing — finds nested paths ffuf/gobuster miss
  // (e.g. /admin/config/backup/). --depth-limits caps recursion so a huge
  // Moodle tree doesn't blow the timeout.
  feroxbuster: {
    bin: 'feroxbuster',
    args: (t) => ['-u', toUrl(t), '-w', '/usr/share/seclists/Discovery/Web-Content/common.txt',
      '-d', '2', '-t', '30', '--timeout', '15', '-s', '200,204,301,302,307,401,403', '-q'],
    desc: 'Recursive directory brute-force',
    timeout: 300000,
  },
  // dirsearch — alternative dir fuzzer with a different default wordlist;
  // catches paths common.txt misses (extension-based: .bak, .zip, .sql).
  dirsearch: {
    bin: 'python3',
    args: (t) => ['-u', '-m', 'dirsearch', '-u', toUrl(t), '-t', '30', '--timeout=10',
      '-x', '404,400', '--no-color', '-q', '-F', 'php,html,bak,zip,sql,txt,json'],
    desc: 'Extension-aware directory search',
    timeout: 300000,
  },
  // gau — fetch known URLs from Wayback/CommonCrawl/OTX. Finds legacy
  // endpoints (old logins, debug pages, deprecated APIs) that live crawls miss.
  gau: {
    bin: 'gau',
    args: (t) => [toHost(t), '--threads', '10', '--timeout', '30', '--o', '/dev/stdout'],
    altArgs: (t) => [toHost(t)],
    desc: 'Wayback/CommonCrawl/OTX URL harvesting',
    timeout: 180000,
  },
  // sslscan — fast TLS cipher/protocol audit (weak ciphers, SSLv3/TLS1.0,
  // self-signed/expired certs). Complements nmap NSE ssl-* scripts.
  sslscan: {
    bin: 'sslscan',
    args: (t) => ['--no-colour', toHost(t)],
    desc: 'TLS/SSL cipher and protocol audit',
    timeout: 120000,
  },
  // masscan — ultra-fast port sweep across the full 65535 range. nmap -sCV
  // only covers top ports; masscan finds the odd high-port service.
  // --rate capped to be network-polite on shared LANs.
  masscan: {
    bin: 'masscan',
    args: (t) => [toHost(t), '-p', '1-65535', '--rate', '500', '--wait', '3', '--open-only'],
    desc: 'Full-range fast port sweep',
    timeout: 240000,
  },
  // searchsploit — local ExploitDB search. Run against fingerprinted
  // software (whatweb/nmap output) to map CVEs to public exploits.
  searchsploit: {
    bin: 'searchsploit',
    args: (t) => ['--color', '-t', toHost(t)],
    desc: 'ExploitDB search',
    timeout: 60000,
  },
}

/** Check availability of all native tools. */
export async function nativeToolsStatus() {
  const status = {}
  for (const [name, def] of Object.entries(NATIVE_TOOLS)) {
    status[name] = await which(def.bin)
  }
  return status
}

/**
 * Run a raw shell command string (bash -c) with the same PATH extras / timeout
 * handling as runNativeTool. Used by the exploit orchestrator for tools that
 * have no NATIVE_TOOLS mapping (hydra, hashcat, responder, crackmapexec,
 * impacket scripts, …) where the registry already stores the full arg-string.
 */
export async function runNativeCommand(command, { timeout = TIMEOUT_MS } = {}) {
  if (!command || typeof command !== 'string') {
    return { success: false, error: 'no command provided' }
  }
  const result = await run('bash', ['-c', command], { timeout })
  return { ...result, command }
}

/**
 * Build the exact command string for a native tool invocation (for live-output
 * display). Special-cases bash -c / python3 -m wrappers so the displayed
 * command matches what actually runs in the shell.
 */
export function previewNativeCommand(moduleName, target) {
  const def = NATIVE_TOOLS[moduleName]
  if (!def) return `${moduleName} ${target}`
  const args = def.args(target)
  if (def.bin === 'bash' && args[0] === '-c') return `bash -c ${JSON.stringify(args[1])}`
  return [def.bin, ...args].join(' ')
}

/** Run a native tool by module name. */
export async function runNativeTool(moduleName, target) {
  const def = NATIVE_TOOLS[moduleName]
  if (!def) return { success: false, error: `no-native-mapping:${moduleName}` }

  // Try primary binary, then alternates (e.g. httpx-toolkit for ProjectDiscovery)
  const bins = [def.bin, ...(def.altBins || [])]
  let bin = null
  for (const b of bins) {
    if (await which(b)) { bin = b; break }
  }
  if (!bin) return { success: false, error: `${bins.join('/')} not found in PATH` }

  const args = def.args(target)
  const toolTimeout = def.timeout || TIMEOUT_MS
  let result = await run(bin, args, { timeout: toolTimeout })

  // Retry once on transient network errors (connection reset / refused / DNS
  // hiccup) — tools often succeed on the second attempt. Only retry when there
  // was NO output at all: partial output means the tool already did real work.
  const TRANSIENT = /connection (reset|refused|timed out)|econnreset|econnrefused|etimedout|network is unreachable|temporary failure|name or service not known|no route to host/i
  if (!result.success && !result.stdout && TRANSIENT.test(result.error || '')) {
    await new Promise((r) => setTimeout(r, 2000))
    result = await run(bin, args, { timeout: toolTimeout })
  }

  // If the primary arg-set failed (unsupported flags / broken env), retry with
  // the simpler altArgs (e.g. Python httpx without ProjectDiscovery flags).
  if (!result.success && def.altArgs) {
    const alt = def.altArgs(target)
    const retry = await run(bin, alt, { timeout: toolTimeout })
    if (retry.success || retry.stdout) {
      return { ...retry, tool: moduleName, bin, args: alt.join(' ') }
    }
  }

  // If still failing and a fallback definition exists (e.g. dnsbrute → dnsrecon),
  // try the fallback tool instead.
  if (!result.success && def.fallbackDef) {
    const fbDef = NATIVE_TOOLS[def.fallbackDef]
    if (fbDef) {
      const fbBin = fbDef.bin
      if (await which(fbBin)) {
        const fbArgs = fbDef.args(target)
        const fbResult = await run(fbBin, fbArgs, { timeout: fbDef.timeout || toolTimeout })
        if (fbResult.success || fbResult.stdout) {
          return { ...fbResult, tool: moduleName, bin: fbBin, args: fbArgs.join(' '), _fallback: def.fallbackDef }
        }
      }
    }
  }

  // Certain tools (like gobuster/dnsbrute/whatweb) return exit code 1 or 2 when no findings are discovered.
  // If the process completed without timing out or signal death, treat as successful execution.
  if (!result.success && !result.timedOut && (result.code === 1 || result.code === 2 || result.stdout)) {
    result.success = true
  }

  return { ...result, tool: moduleName, bin, args: args.join(' ') }
}

export default { nativeToolsStatus, runNativeTool, runNativeCommand, previewNativeCommand, NATIVE_TOOLS }
