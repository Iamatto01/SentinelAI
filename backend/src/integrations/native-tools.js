import { spawn } from 'node:child_process'
import { config } from '../config.js'

/**
 * Native tool runner — executes security tools directly via child_process.
 * Used when HexStrike output capture fails (subfinder, httpx, katana, dalfox,
 * wpscan) or as a fallback when HexStrike is unavailable.
 *
 * Only used when backend runs on the same machine as the tools (Kali all-in-one).
 */

const TIMEOUT_MS = config.hexstrike?.timeoutMs || 600000

/** Check if a binary exists in PATH. */
async function which(bin) {
  return new Promise((resolve) => {
    const proc = spawn('which', [bin], { shell: true })
    proc.on('close', (code) => resolve(code === 0))
    proc.on('error', () => resolve(false))
  })
}

/** Run a command, capture stdout/stderr, respect timeout. */
async function run(cmd, args, { timeout = TIMEOUT_MS } = {}) {
  return new Promise((resolve) => {
    // Ensure Go/Python gem tool paths are reachable regardless of caller env
    const extra = [
      '/usr/local/bin', '/usr/local/sbin',
      '/root/go/bin', '/root/.local/bin',
      '/usr/lib/ruby/gems/*/bin', '/var/lib/gems/*/bin',
      process.env.HOME ? `${process.env.HOME}/go/bin` : null,
      process.env.HOME ? `${process.env.HOME}/.local/bin` : null,
    ].filter(Boolean).join(':')
    const env = { ...process.env, PATH: `${process.env.PATH || ''}:${extra}` }
    const proc = spawn(cmd, args, { shell: true, stdio: ['ignore', 'pipe', 'pipe'], env })
    let stdout = ''
    let stderr = ''
    const timer = setTimeout(() => {
      proc.kill('SIGKILL')
      resolve({ success: false, stdout, stderr, error: `timeout after ${timeout}ms` })
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

/**
 * Native tool definitions: binary name, argument builder, and whether we need
 * to strip the scheme (host tools) or keep it (URL tools).
 */
const NATIVE_TOOLS = {
  subfinder: {
    bin: 'subfinder',
    args: (t) => ['-d', toHost(t), '-silent'],
    desc: 'Subdomain enumeration',
  },
  // Active DNS brute-force — finds subdomains passive sources miss (aziz., dev., staging.)
  // Primary: gobuster dns. Falls back to dnsrecon if gobuster's -d parser rejects
  // the domain (known gobuster v3.0 bug with hyphenated domains like "myces-fms.com").
  dnsbrute: {
    bin: 'gobuster',
    fallbackDef: 'dnsrecon',  // runNativeTool will try this if gobuster fails
    args: (t) => {
      // Extract the registrable domain (last 2 parts) — gobuster -d needs the apex
      let bare = t.replace(/^https?:\/\//i, '').split('/')[0].replace(/^\*\./, '').trim().toLowerCase()
      const parts = bare.split('.')
      if (parts.length > 2) bare = parts.slice(-2).join('.')  // www.myces-fms.com → myces-fms.com
      return ['dns', '-d', bare, '-w', '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt', '-q', '-t', '30', '--timeout', '10s']
    },
    // Simpler invocation for older gobuster builds that reject --timeout.
    altArgs: (t) => {
      let bare = t.replace(/^https?:\/\//i, '').split('/')[0].replace(/^\*\./, '').trim().toLowerCase()
      const parts = bare.split('.')
      if (parts.length > 2) bare = parts.slice(-2).join('.')
      return ['dns', '-d', bare, '-w', '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt', '-q']
    },
    desc: 'Subdomain brute-force',
  },
  // dnsrecon fallback — invoked when gobuster's -d flag rejects the domain.
  // Uses its own wordlist; -D for subdomain brute, -t std.
  dnsrecon: {
    bin: 'dnsrecon',
    args: (t) => {
      let bare = t.replace(/^https?:\/\//i, '').split('/')[0].replace(/^\*\./, '').trim().toLowerCase()
      const parts = bare.split('.')
      if (parts.length > 2) bare = parts.slice(-2).join('.')
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
    bin: 'katana',
    args: (t) => ['-u', toUrl(t), '-silent', '-json', '-d', '3', '-timeout', '30', '-rate-limit', '150'],
    // Older katana builds reject -rate-limit; retry with minimal flags.
    altArgs: (t) => ['-u', toUrl(t), '-silent', '-d', '2'],
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
    desc: 'SQL injection testing',
  },
  arjun: {
    bin: 'arjun',
    args: (t) => ['-u', toUrl(t), '--stable', '-c', '30', '-t', '3'],
    // Arjun is notoriously slow on large apps. Cap at 2 minutes, use 30 threads.
    parameterDiscovery: true,
    timeout: 120000,
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
    args: (t) => ['-u', toUrl(t), '-silent', '-json', '-timeout', '30', '-rate-limit', '150', '-no-mh'],
    // Older nuclei versions reject -rate-limit / -no-mh; retry with minimal flags.
    altArgs: (t) => ['-u', toUrl(t), '-silent', '-json'],
    // Some nuclei builds (v2.x) need -target instead of -u; fallback via altBins.
    altBins: ['nuclei'],
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
  'nmap-script': {
    bin: 'nmap',
    args: (t) => t.split(' ').filter(Boolean),
    desc: 'Nmap NSE script probe',
  },
  // Interactive console — run arbitrary commands (e.g., telnet, nc, curl, hydra, msfconsole)
  console: {
    bin: 'bash',
    args: (t) => ['-c', t],
    desc: 'Arbitrary command execution',
    timeout: 120000, // 2 min default — customizable per invocation
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

export default { nativeToolsStatus, runNativeTool, NATIVE_TOOLS }
