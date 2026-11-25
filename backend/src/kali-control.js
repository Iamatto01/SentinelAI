import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawn } from 'node:child_process'
import { llm } from './ai/llm-client.js'
import { config } from './config.js'

let spawnImpl = spawn

/** Test hook to intercept process spawning cleanly without hitting live OS tools. */
export function __setSpawnForTest(fn) {
  spawnImpl = typeof fn === 'function' ? fn : spawn
}

export const ALLOWED_COMMANDS = Object.freeze([
  'nmap', 'nikto', 'nuclei', 'gobuster', 'feroxbuster', 'sqlmap', 'ffuf',
  'dirsearch', 'wafw00f', 'subfinder', 'amass', 'masscan', 'sslscan', 'whatweb',
  'wpscan', 'hydra', 'msfconsole', 'msfrpcd', 'httpx', 'katana', 'dalfox', 'arjun',
  'whois', 'dig', 'nslookup', 'host', 'traceroute', 'tracert', 'ping', 'curl', 'wget',
  'python3', 'python', 'ruby', 'perl', 'go', 'node',
  'netstat', 'ss', 'ps', 'top', 'htop', 'free', 'df', 'du', 'ls', 'cat', 'head', 'tail',
  'grep', 'find', 'locate', 'which', 'whereis', 'file', 'stat', 'strings', 'xxd', 'hexdump',
  'awk', 'sed', 'sort', 'uniq', 'wc', 'cut', 'tr', 'tee', 'tar', 'gzip', 'zip', 'unzip',
  'ifconfig', 'ip', 'iwconfig', 'rfkill', 'arp', 'route', 'tcpdump', 'tshark',
  'systemctl', 'journalctl', 'service', 'docker', 'uptime', 'uname', 'who', 'w', 'id', 'whoami',
  'last', 'lastlog', 'crontab', 'date', 'vmstat', 'iostat', 'lsof', 'getent',
  'passwd', 'chage', 'ufw', 'iptables', 'fail2ban-client',
  'git', 'make', 'cmake', 'gcc', 'g++',
  'pip', 'pip3', 'npm', 'yarn', 'gem', 'cpan',
  'echo', 'true', 'false', 'env', 'printenv', 'pwd',
  'ssh', 'scp', 'rsync', 'nc', 'ncat', 'socat',
  'base64', 'openssl', 'gpg',
  'snmpwalk', 'snmpget', 'enum4linux', 'smbclient', 'smbmap', 'rpcclient',
  'aircrack-ng', 'airodump-ng', 'aireplay-ng', 'reaver', 'wash', 'kismet',
  'searchsploit', 'exploitdb',
])

const ALLOWED_COMMAND_SET = new Set(ALLOWED_COMMANDS)
const TRUSTED_BIN_DIRS = new Set(['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/local/bin', '/usr/local/sbin'])
const INTERACTIVE_TOOLS = new Set(['nano', 'vim', 'vi', 'less', 'more'])
const SHELL_METACHAR_RE = /[;&|`><\r\n\0]|\$\(|\$\{/

const INTERPRETER_FLAG_VALIDATORS = {
  python: validatePythonArgs,
  python3: validatePythonArgs,
  node: validateNodeArgs,
  ruby: validateRubyArgs,
  perl: validatePerlArgs,
  find: validateFindArgs,
  nmap: validateNmapArgs,
  tar: validateTarArgs,
  git: validateGitArgs,
  awk: validateAwkArgs,
  env: validateEnvArgs,
}

function validatePythonArgs(args) {
  for (const arg of args) {
    if (arg === '-' || arg === '--command' || arg.startsWith('--command=') || arg === '--interactive' || /^-[^-]*[ci]/.test(arg)) {
      throw new Error(`Disallowed interpreter flag for python: ${arg}`)
    }
  }
}

function validateNodeArgs(args) {
  const blockedExact = new Set([
    '-', '--eval', '--print', '--require', '--import', '--loader', '--experimental-loader', '--interactive',
  ])
  const blockedPrefix = ['--eval=', '--print=', '--require=', '--import=', '--loader=', '--experimental-loader=']
  for (const arg of args) {
    if (blockedExact.has(arg) || blockedPrefix.some((p) => arg.startsWith(p)) || /^-[^-]*[epri]/.test(arg)) {
      throw new Error(`Disallowed interpreter flag for node: ${arg}`)
    }
  }
}

function validateRubyArgs(args) {
  for (const arg of args) {
    if (arg === '-' || arg === '--eval' || arg.startsWith('--eval=') || arg === '--require' || arg.startsWith('--require=') || /^-[^-]*[er]/.test(arg)) {
      throw new Error(`Disallowed interpreter flag for ruby: ${arg}`)
    }
  }
}

function validatePerlArgs(args) {
  for (const arg of args) {
    if (arg === '-' || /^-[^-]*[eEMi]/.test(arg)) {
      throw new Error(`Disallowed interpreter flag for perl: ${arg}`)
    }
  }
}

function validateFindArgs(args) {
  const blocked = new Set(['-exec', '-execdir', '-ok', '-okdir'])
  for (const arg of args) {
    if (blocked.has(arg)) {
      throw new Error(`Disallowed execution flag for find: ${arg}`)
    }
  }
}

function validateNmapArgs(args) {
  for (const arg of args) {
    if (arg === '--interactive') {
      throw new Error('Interactive nmap mode is not supported')
    }
  }
}

function validateTarArgs(args) {
  const blockedPrefix = ['--to-command', '--checkpoint-action', '--use-compress-program']
  for (const arg of args) {
    if (arg === '-I' || blockedPrefix.some((p) => arg === p || arg.startsWith(`${p}=`))) {
      throw new Error(`Disallowed execution flag for tar: ${arg}`)
    }
  }
}

function validateGitArgs(args) {
  const blockedPrefix = ['--upload-pack', '--receive-pack', '--exec', '--exec-path']
  for (const arg of args) {
    if (arg === '-c' || arg.startsWith('-c') || blockedPrefix.some((p) => arg === p || arg.startsWith(`${p}=`))) {
      throw new Error(`Disallowed execution/config flag for git: ${arg}`)
    }
  }
}

function validateAwkArgs(args) {
  for (const arg of args) {
    if (/system\s*\(|\|&|\bgetline\b/i.test(arg)) {
      throw new Error('Disallowed command execution construct in awk')
    }
  }
}

function validateEnvArgs(args) {
  let expectFlagVal = false
  for (const arg of args) {
    if (expectFlagVal) {
      expectFlagVal = false
      continue
    }
    if (arg === '-u' || arg === '--unset') {
      expectFlagVal = true
      continue
    }
    if (!arg.startsWith('-')) {
      throw new Error('Executing arbitrary commands via env is not permitted')
    }
  }
}

/** Tokenize a command string safely into argv tokens without shell expansion. */
export function tokenizeCommand(command) {
  if (!command || typeof command !== 'string') {
    throw new Error('Command is required')
  }
  const trimmed = command.trim()
  if (!trimmed) {
    throw new Error('Command is required')
  }
  if (SHELL_METACHAR_RE.test(trimmed)) {
    throw new Error('Shell metacharacters (;, &, |, backticks, $(), redirects, newlines) are not allowed')
  }

  const tokens = []
  let current = ''
  let quote = null
  let tokenStarted = false

  for (let i = 0; i < trimmed.length; i++) {
    const ch = trimmed[i]
    if (quote === "'") {
      if (ch === "'") {
        quote = null
      } else {
        current += ch
      }
      tokenStarted = true
      continue
    }
    if (quote === '"') {
      if (ch === '"') {
        quote = null
      } else if (ch === '\\' && i + 1 < trimmed.length && (trimmed[i + 1] === '"' || trimmed[i + 1] === '\\')) {
        current += trimmed[++i]
      } else {
        current += ch
      }
      tokenStarted = true
      continue
    }
    if (/\s/.test(ch)) {
      if (tokenStarted) {
        tokens.push(current)
        current = ''
        tokenStarted = false
      }
      continue
    }
    if (ch === "'" || ch === '"') {
      quote = ch
      tokenStarted = true
      continue
    }
    if (ch === '\\' && i + 1 < trimmed.length) {
      current += trimmed[++i]
      tokenStarted = true
      continue
    }
    current += ch
    tokenStarted = true
  }

  if (quote !== null) {
    throw new Error('Unclosed quote in command')
  }
  if (tokenStarted) {
    tokens.push(current)
  }
  if (tokens.length === 0) {
    throw new Error('Command is required')
  }
  return tokens
}

/** Validate and parse a user command into safe `{ bin, execTarget, args, maxLines }`. */
export function parseAndValidateCommand(command) {
  const [rawBin, ...args] = tokenizeCommand(command)

  if (rawBin.includes('..') || rawBin.includes('\\')) {
    throw new Error(`Invalid command path: ${rawBin}`)
  }

  let bin = rawBin
  let execTarget = rawBin
  if (rawBin.includes('/')) {
    const dir = path.posix.dirname(rawBin)
    bin = path.posix.basename(rawBin)
    if (!TRUSTED_BIN_DIRS.has(dir)) {
      throw new Error(`Untrusted binary directory: ${dir}`)
    }
  }

  if (INTERACTIVE_TOOLS.has(bin)) {
    throw new Error(`Interactive editor/pager (${bin}) is not supported in web terminal. Use 'cat', 'head -n 50', or 'tail -n 50' to view files.`)
  }
  if (!ALLOWED_COMMAND_SET.has(bin)) {
    throw new Error(`Command not allowed: ${bin}. Use the AI suggest feature or request a tool addition.`)
  }

  const validator = INTERPRETER_FLAG_VALIDATORS[bin]
  if (validator) validator(args)

  if (bin === 'htop') {
    return { bin, execTarget: 'top', args: ['-b', '-n', '1'], maxLines: 35 }
  }
  if (bin === 'top' && !args.includes('-b')) {
    return { bin, execTarget: 'top', args: ['-b', '-n', '1'], maxLines: 35 }
  }

  return { bin, execTarget, args, maxLines: null }
}

/** Build a shell-free sudo invocation passing password over stdin (`sudo -S -p ''`). */
export function buildSudoInvocation(cmdArgs, password = config.kaliSudoPassword) {
  if (!Array.isArray(cmdArgs) || cmdArgs.length === 0) {
    throw new Error('sudo command arguments are required')
  }
  if (password) {
    return {
      bin: 'sudo',
      args: ['-S', '-p', '', ...cmdArgs],
      stdinData: `${password}\n`,
    }
  }
  return {
    bin: 'sudo',
    args: [...cmdArgs],
    stdinData: null,
  }
}

function buildExecEnv() {
  const extra = [
    '/usr/local/bin', '/usr/local/sbin', '/usr/bin', '/bin',
    '/root/go/bin', '/root/.local/bin',
    '/home/kali/go/bin', '/home/kali/.local/bin',
    process.env.HOME ? `${process.env.HOME}/go/bin` : null,
    process.env.HOME ? `${process.env.HOME}/.local/bin` : null,
  ].filter(Boolean).join(':')

  return {
    ...process.env,
    PATH: `${process.env.PATH || ''}:${extra}`,
    TERM: 'xterm-256color',
    COLUMNS: '120',
    LINES: '40',
  }
}

/** Execute a binary directly with argument array and shell: false. */
async function runBinary(bin, args = [], { timeoutMs = 30000, stdinData = null } = {}) {
  return new Promise((resolve) => {
    const proc = spawnImpl(bin, args, {
      shell: false,
      stdio: [stdinData !== null ? 'pipe' : 'ignore', 'pipe', 'pipe'],
      env: buildExecEnv(),
      detached: process.platform !== 'win32',
    })

    let stdout = ''
    let stderr = ''

    const timer = setTimeout(() => {
      try { process.kill(-proc.pid, 'SIGKILL') } catch { try { proc.kill('SIGKILL') } catch { /* ignore */ } }
      resolve({ success: false, stdout, stderr, error: `Command timed out after ${timeoutMs / 1000}s`, code: 124 })
    }, timeoutMs)

    if (stdinData !== null && proc.stdin) {
      proc.stdin.on('error', () => { /* ignore EPIPE if child exits early */ })
      proc.stdin.write(stdinData)
      proc.stdin.end()
    }

    proc.stdout?.on('data', (d) => { stdout += d.toString() })
    proc.stderr?.on('data', (d) => { stderr += d.toString() })

    proc.on('close', (code) => {
      clearTimeout(timer)
      resolve({
        success: code === 0,
        code,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        error: code !== 0 ? (stderr.trim() || `Exit code ${code}`) : null,
      })
    })

    proc.on('error', (err) => {
      clearTimeout(timer)
      resolve({ success: false, error: err.message, stdout: stdout.trim(), stderr: stderr.trim(), code: 1 })
    })
  })
}

async function runSudoCommand(cmdArgs, options = {}) {
  const { bin, args, stdinData } = buildSudoInvocation(cmdArgs)
  return runBinary(bin, args, { ...options, stdinData })
}

/** Check if a binary exists in PATH without invoking a shell */
async function checkBin(bin) {
  if (!/^[A-Za-z0-9._+-]+$/.test(bin)) return null
  const res = await runBinary('which', [bin], { timeoutMs: 3000 })
  return res.success ? res.stdout.split('\n')[0].trim() : null
}

/** Check service status via systemctl or port */
async function checkService(name, port) {
  try {
    let active = false
    let details = 'stopped'

    if (process.platform === 'linux') {
      const res = await runBinary('systemctl', ['is-active', name], { timeoutMs: 3000 })
      if (res.stdout.trim() === 'active') {
        active = true
        details = 'active (systemd)'
      }
    }

    if (port) {
      const portRes = await runBinary('ss', ['-tlnp'], { timeoutMs: 3000 })
      if (portRes.success && portRes.stdout.split(/\r?\n/).some((line) => line.includes(`:${port} `))) {
        active = true
        details = `listening on port ${port}`
      }
    }

    return { active, details }
  } catch {
    return { active: false, details: 'unknown' }
  }
}

/** Get system information and metrics */
export async function getSystemInfo() {
  const hostname = os.hostname()
  const platform = os.platform()
  const release = os.release()
  const arch = os.arch()
  const uptimeSec = os.uptime()
  const cpus = os.cpus()
  const loadAvg = os.loadavg()
  const totalMem = os.totalmem()
  const freeMem = os.freemem()
  const usedMem = totalMem - freeMem
  const memUsagePercent = Math.round((usedMem / totalMem) * 100)

  const interfaces = os.networkInterfaces()
  const networkIps = []
  for (const [iface, addrs] of Object.entries(interfaces)) {
    for (const addr of addrs || []) {
      if (addr.family === 'IPv4' && !addr.internal) {
        networkIps.push({ iface, address: addr.address, netmask: addr.netmask })
      }
    }
  }

  const formatDiskUnit = (val) => {
    if (!val || typeof val !== 'string') return val || '0 GB'
    if (/\s*(GB|MB|TB|KB)$/i.test(val)) return val
    return val
      .replace(/([0-9.]+)G$/i, '$1 GB')
      .replace(/([0-9.]+)M$/i, '$1 MB')
      .replace(/([0-9.]+)T$/i, '$1 TB')
      .replace(/([0-9.]+)K$/i, '$1 KB')
  }

  let disk = { total: 'N/A', used: 'N/A', free: 'N/A', percent: 'N/A' }
  try {
    const checkPath = (config.outputDir && fs.existsSync(config.outputDir)) ? config.outputDir : '/'
    const dfRes = await runBinary('df', ['-h', checkPath], { timeoutMs: 3000 })
    const lastLine = dfRes.stdout.split(/\r?\n/).filter(Boolean).pop()
    if (dfRes.success && lastLine) {
      const parts = lastLine.split(/\s+/)
      if (parts.length >= 5) {
        disk = {
          total: formatDiskUnit(parts[1]),
          used: formatDiskUnit(parts[2]),
          free: formatDiskUnit(parts[3]),
          percent: parts[4],
          mount: parts[5] || checkPath,
          rawTotal: parts[1],
          rawUsed: parts[2],
        }
      }
    }
  } catch { /* ignore */ }

  const services = {
    sentinelai: await checkService('sentinelai', 5000),
    msfrpcd: await checkService('msfrpcd', 55553),
    cloudflared: await checkService('cloudflared', null),
    avahi: await checkService('avahi-daemon', null),
  }

  return {
    hostname,
    platform,
    release,
    arch,
    uptimeSec,
    cpuCount: cpus.length,
    cpuModel: cpus[0]?.model || 'Generic CPU',
    loadAvg,
    memory: {
      totalBytes: totalMem,
      usedBytes: usedMem,
      freeBytes: freeMem,
      totalMb: Math.round(totalMem / (1024 * 1024)),
      usedMb: Math.round(usedMem / (1024 * 1024)),
      freeMb: Math.round(freeMem / (1024 * 1024)),
      percent: memUsagePercent,
    },
    disk,
    networkIps,
    services,
  }
}

/** Execute an allowlisted command from web console without shell interpretation */
export async function executeCommand(command, timeout = 30000) {
  const { execTarget, args, maxLines } = parseAndValidateCommand(command)
  const result = await runBinary(execTarget, args, { timeoutMs: timeout })
  if (maxLines && result.stdout) {
    result.stdout = result.stdout.split(/\r?\n/).slice(0, maxLines).join('\n')
  }
  return result
}

/**
 * AI Chatbox: translate a natural-language request into a single Kali command
 * aligned with executeCommand()'s allowlist. Returns { command, explanation, risk }.
 */
export async function suggestKaliCommand(message, history = []) {
  if (!message || typeof message !== 'string' || !message.trim()) {
    throw new Error('Message is required')
  }
  if (!llm.isConfigured()) {
    throw new Error('No AI provider configured — set an API key in Settings')
  }

  const ctx = history.slice(-6).map((h) => `${h.role}: ${h.content}`).join('\n')
  const prompt = `${ctx ? ctx + '\n' : ''}user: ${message}

You are the command planner for a Kali Linux pentest box. Convert the user's natural-language request into ONE ready-to-run command from the allowed console allowlist.

Rules:
1. Output a SINGLE command using only an allowed binary (${ALLOWED_COMMANDS.slice(0, 60).join(', ')}, etc.). NO shell pipelines (|), NO command chaining (;, &&, ||), NO subshells ($(), backticks), NO redirects (>, <), NO multi-line scripts, NO interactive commands (nano, vim, top, less), and NO package managers (apt, apt-get, dpkg) or destructive system binaries (rm, mkfs, dd, shutdown).
2. Prefer read-only/diagnostic commands (df, free, ss, ps, ip, ls, cat, tail, head, systemctl status, journalctl, docker ps, nmap -sV without exploitation flags).
3. For disruptive/privileged allowed commands (such as systemctl restart, ufw, iptables), still provide the single allowed command and set risk to "high".
4. Use built-in output-limiting flags (e.g. "tail -n 20", "head -n 50", "journalctl -n 50 --no-pager") instead of shell pipes.
5. If the request requires blocked tools, shell piping/chaining, or is not security/host-related, set command to "" and explain why.

Respond ONLY with JSON:
{
  "command": "the exact command to run",
  "explanation": "one short sentence explaining what this command does",
  "risk": "low" | "medium" | "high"
}`

  const system = 'You are a precise Kali Linux operations assistant. You output strict JSON only — no markdown fences, no prose outside JSON.'
  const raw = await llm.analyze(prompt, {
    system,
    context: { operation: 'kali-command-suggest', agent: 'recon-advisor' },
    useFast: true,
    maxTokens: 1000,
    timeoutMs: 45000,
  })

  const cleaned = String(raw)
    .replace(/<think>[\s\S]*?<\/think>/gi, '')
    .replace(/^```(json)?/i, '')
    .replace(/```/g, '')
    .trim()

  let parsed
  try {
    parsed = JSON.parse(cleaned)
  } catch {
    const candidates = []
    const greedy = cleaned.match(/\{[\s\S]*\}/)
    if (greedy) candidates.push(greedy[0])
    for (const m of cleaned.matchAll(/\{[^{}]*\}/g)) candidates.push(m[0])
    for (const c of candidates) {
      try {
        parsed = JSON.parse(c)
        break
      } catch { /* try next candidate */ }
    }
    if (!parsed) {
      const cmdLine = cleaned.split('\n').map((l) => l.trim()).find((l) => {
        if (!l || /[.?!]$/.test(l)) return false
        try {
          parseAndValidateCommand(l)
          return true
        } catch {
          return false
        }
      })
      if (cmdLine) {
        parsed = { command: cmdLine, explanation: 'Parsed from AI free-text response', risk: 'medium' }
      } else {
        throw new Error('AI could not produce a command for this request')
      }
    }
  }

  const command = String(parsed.command || '').trim()
  if (!command) {
    throw new Error(parsed.explanation || 'AI declined to produce a command for this request')
  }

  try {
    parseAndValidateCommand(command)
  } catch (err) {
    throw new Error(`AI suggested a command not permitted by console policy: ${err.message}`)
  }

  return {
    command,
    explanation: parsed.explanation || '',
    risk: ['low', 'medium', 'high'].includes(parsed.risk) ? parsed.risk : 'medium',
  }
}

/** Manage Kali Services */
export async function manageService(service, action) {
  const allowedServices = ['sentinelai', 'msfrpcd', 'cloudflared', 'avahi-daemon']
  const allowedActions = ['start', 'stop', 'restart', 'status']

  if (!allowedServices.includes(service)) {
    throw new Error(`Invalid service. Allowed: ${allowedServices.join(', ')}`)
  }
  if (!allowedActions.includes(action)) {
    throw new Error(`Invalid action. Allowed: ${allowedActions.join(', ')}`)
  }

  if (service === 'msfrpcd' && action === 'status') {
    const sysRes = await runBinary('systemctl', ['is-active', 'sentinelai'], { timeoutMs: 15000 })
    const ssRes = await runBinary('ss', ['-lntp'], { timeoutMs: 15000 })
    const portMatches = ssRes.stdout.split(/\r?\n/).filter((line) => line.includes(':55553'))
    const portOut = portMatches.length ? portMatches.join('\n') : 'port 55553 not listening'
    return {
      success: sysRes.success || portMatches.length > 0,
      code: sysRes.code,
      stdout: [sysRes.stdout, portOut].filter(Boolean).join('\n'),
      stderr: sysRes.stderr,
      error: null,
    }
  }

  const targetUnit = service === 'msfrpcd' ? 'sentinelai' : service
  return runSudoCommand(['systemctl', action, targetUnit], { timeoutMs: 15000 })
}

/** Audit all 20 Pentest Tools */
export async function auditTools() {
  const tools = [
    { name: 'nmap', category: 'Recon & Port Scan', desc: 'Network mapper & port scanner' },
    { name: 'masscan', category: 'Recon & Port Scan', desc: 'High-speed SYN port scanner' },
    { name: 'whatweb', category: 'Recon & Port Scan', desc: 'Web technology recognizer' },
    { name: 'sslscan', category: 'Recon & Port Scan', desc: 'TLS/SSL cipher auditor' },
    { name: 'wafw00f', category: 'Recon & Port Scan', desc: 'WAF detection tool' },
    { name: 'subfinder', category: 'Subdomain & DNS', desc: 'Fast passive subdomain discovery' },
    { name: 'amass', category: 'Subdomain & DNS', desc: 'In-depth attack surface mapping' },
    { name: 'httpx', category: 'Subdomain & DNS', desc: 'Fast HTTP probe & tech identifier' },
    { name: 'gobuster', category: 'Web Fuzzing', desc: 'URI directory & DNS brute forcer' },
    { name: 'feroxbuster', category: 'Web Fuzzing', desc: 'Fast recursive content discovery' },
    { name: 'dirsearch', category: 'Web Fuzzing', desc: 'Web path brute-force tool' },
    { name: 'ffuf', category: 'Web Fuzzing', desc: 'High performance web fuzzer' },
    { name: 'katana', category: 'Web Fuzzing', desc: 'Next-gen web crawler & spider' },
    { name: 'nuclei', category: 'Vulnerability Scanner', desc: 'Template-based vulnerability scanner' },
    { name: 'nikto', category: 'Vulnerability Scanner', desc: 'Web server vulnerability scanner' },
    { name: 'sqlmap', category: 'Vulnerability Scanner', desc: 'Automated SQL injection tool' },
    { name: 'wpscan', category: 'Vulnerability Scanner', desc: 'WordPress security scanner' },
    { name: 'arjun', category: 'Vulnerability Scanner', desc: 'HTTP parameter discovery suite' },
    { name: 'dalfox', category: 'Vulnerability Scanner', desc: 'Parameter analysis & XSS scanner' },
    { name: 'hydra', category: 'Exploitation & Cracking', desc: 'Fast network logon cracker' },
  ]

  const audited = []
  for (const t of tools) {
    const binPath = await checkBin(t.name)
    audited.push({
      ...t,
      installed: Boolean(binPath),
      path: binPath || null,
    })
  }

  const installedCount = audited.filter((t) => t.installed).length
  return {
    total: audited.length,
    installed: installedCount,
    missing: audited.length - installedCount,
    tools: audited,
  }
}

/** Run tool installation steps sequentially without shell interpolation */
export async function runToolsInstallSteps() {
  await runSudoCommand(['apt', 'update', '-y'], { timeoutMs: 120000 })
  await runSudoCommand([
    'apt', 'install', '-y',
    'nmap', 'nikto', 'nuclei', 'gobuster', 'feroxbuster', 'sqlmap', 'ffuf',
    'dirsearch', 'wafw00f', 'subfinder', 'amass', 'masscan', 'sslscan',
    'whatweb', 'wpscan', 'hydra', 'avahi-daemon', 'avahi-utils', 'libnss-mdns',
    'python3-pip', 'httpx-toolkit',
  ], { timeoutMs: 300000 })

  await runBinary('pip3', ['install', 'arjun', '--break-system-packages'], { timeoutMs: 120000 })
  await runBinary('go', ['install', 'github.com/projectdiscovery/katana/cmd/katana@latest'], { timeoutMs: 120000 })
  await runBinary('go', ['install', 'github.com/hahwul/dalfox/v2@latest'], { timeoutMs: 120000 })

  const goBinDir = path.join(os.homedir(), 'go', 'bin')
  for (const tool of ['katana', 'dalfox']) {
    const src = path.join(goBinDir, tool)
    if (fs.existsSync(src)) {
      await runSudoCommand(['cp', src, `/usr/local/bin/${tool}`], { timeoutMs: 15000 })
    }
  }

  const httpxToolkit = await checkBin('httpx-toolkit')
  if (httpxToolkit) {
    await runSudoCommand(['ln', '-sf', httpxToolkit, '/usr/local/bin/httpx'], { timeoutMs: 15000 })
  }
}

/** Trigger background installation/update of all tools */
export function triggerToolsInstall() {
  setImmediate(async () => {
    try {
      await runToolsInstallSteps()
    } catch (e) {
      console.error('[kali-control] Tools install error:', e.message)
    }
  })

  return { ok: true, message: 'Tool installation initiated in background' }
}
