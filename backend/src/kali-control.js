import fs from 'node:fs'
import os from 'node:os'
import { spawn } from 'node:child_process'
import { llm } from './ai/llm-client.js'
import { config } from './config.js'

/** Execute a command with timeout and environment extras */
async function runCmd(cmd, timeoutMs = 30000) {
  return new Promise((resolve) => {
    const extra = [
      '/usr/local/bin', '/usr/local/sbin', '/usr/bin', '/bin',
      '/root/go/bin', '/root/.local/bin',
      '/home/kali/go/bin', '/home/kali/.local/bin',
      process.env.HOME ? `${process.env.HOME}/go/bin` : null,
      process.env.HOME ? `${process.env.HOME}/.local/bin` : null,
    ].filter(Boolean).join(':')

    const env = {
      ...process.env,
      PATH: `${process.env.PATH || ''}:${extra}`,
      TERM: 'xterm-256color',
      COLUMNS: '120',
      LINES: '40',
    }
    const proc = spawn(cmd, { shell: true, stdio: ['ignore', 'pipe', 'pipe'], env, detached: true })
    let stdout = ''
    let stderr = ''

    const timer = setTimeout(() => {
      try { process.kill(-proc.pid, 'SIGKILL') } catch { proc.kill('SIGKILL') }
      resolve({ success: false, stdout, stderr, error: `Command timed out after ${timeoutMs / 1000}s`, code: 124 })
    }, timeoutMs)

    proc.stdout.on('data', (d) => { stdout += d.toString() })
    proc.stderr.on('data', (d) => { stderr += d.toString() })

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

/** Check if a binary exists in PATH */
async function checkBin(bin) {
  const res = await runCmd(`command -v ${bin}`, 3000)
  return res.success ? res.stdout.split('\n')[0].trim() : null
}

/** Check service status via systemctl or port */
async function checkService(name, port) {
  try {
    let active = false
    let details = 'stopped'

    // Check systemctl first if on linux
    if (process.platform === 'linux') {
      const res = await runCmd(`systemctl is-active ${name} 2>/dev/null`, 3000)
      if (res.stdout.trim() === 'active') {
        active = true
        details = 'active (systemd)'
      }
    }

    // Check port if specified
    if (port) {
      const portRes = await runCmd(`ss -tlnp 2>/dev/null | grep -E ':${port} '`, 3000)
      if (portRes.success && portRes.stdout) {
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

  // Collect network IPs
  const interfaces = os.networkInterfaces()
  const networkIps = []
  for (const [iface, addrs] of Object.entries(interfaces)) {
    for (const addr of addrs || []) {
      if (addr.family === 'IPv4' && !addr.internal) {
        networkIps.push({ iface, address: addr.address, netmask: addr.netmask })
      }
    }
  }

  // Helper to format disk units (e.g. 47G -> 47 GB, 500M -> 500 MB)
  const formatDiskUnit = (val) => {
    if (!val || typeof val !== 'string') return val || '0 GB'
    if (/\s*(GB|MB|TB|KB)$/i.test(val)) return val
    return val
      .replace(/([0-9.]+)G$/i, '$1 GB')
      .replace(/([0-9.]+)M$/i, '$1 MB')
      .replace(/([0-9.]+)T$/i, '$1 TB')
      .replace(/([0-9.]+)K$/i, '$1 KB')
  }

  // Disk usage via df -h
  let disk = { total: 'N/A', used: 'N/A', free: 'N/A', percent: 'N/A' }
  try {
    const checkPath = (config.outputDir && fs.existsSync(config.outputDir)) ? config.outputDir : '/'
    const dfRes = await runCmd(`df -h "${checkPath}" | tail -n 1`, 3000)
    if (dfRes.success && dfRes.stdout) {
      const parts = dfRes.stdout.split(/\s+/)
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
  } catch { }

  // Check key services
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

/** Execute a command from web console */
export async function executeCommand(command, timeout = 30000) {
  if (!command || typeof command !== 'string') {
    throw new Error('Command is required')
  }

  // Allowlist: only safe read-only/recon/system-status commands
  const allowed = [
    'nmap', 'nikto', 'nuclei', 'gobuster', 'feroxbuster', 'sqlmap', 'ffuf',
    'dirsearch', 'wafw00f', 'subfinder', 'amass', 'masscan', 'sslscan', 'whatweb',
    'wpscan', 'hydra', 'msfconsole', 'msfrpcd', 'httpx', 'katana', 'dalfox', 'arjun',
    'whois', 'dig', 'nslookup', 'host', 'traceroute', 'tracert', 'ping', 'curl', 'wget',
    'python3', 'python', 'ruby', 'perl', 'go', 'node',
    'netstat', 'ss', 'ps', 'top', 'htop', 'free', 'df', 'du', 'ls', 'cat', 'head', 'tail',
    'grep', 'find', 'locate', 'which', 'whereis', 'file', 'stat', 'strings', 'xxd', 'hexdump',
    'awk', 'sed', 'sort', 'uniq', 'wc', 'cut', 'tr', 'tee', 'tar', 'gzip', 'zip', 'unzip',
    'ifconfig', 'ip', 'iwconfig', 'rfkill', 'arp', 'route', 'tcpdump', 'tshark',
    'systemctl', 'journalctl', 'service', 'docker', 'uptime', 'uname', 'who', 'w', 'id',
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
  ]
  const firstWord = command.trim().split(/\s+/)[0]
  const bin = firstWord.replace(/^.*\//, '') // strip path prefix
  if (!allowed.includes(bin)) {
    throw new Error(`Command not allowed: ${bin}. Use the AI suggest feature or request a tool addition.`)
  }

  // Translate interactive commands to non-interactive batch mode
  let finalCmd = command.trim()
  if (bin === 'htop') {
    finalCmd = 'COLUMNS=120 top -b -n 1 | head -n 35'
  } else if (bin === 'top' && !finalCmd.includes('-b')) {
    finalCmd = `COLUMNS=120 top -b -n 1 | head -n 35`
  } else if (['nano', 'vim', 'vi', 'less', 'more'].includes(bin)) {
    throw new Error(`Interactive editor/pager (${bin}) is not supported in web terminal. Use 'cat', 'head -n 50', or 'tail -n 50' to view files.`)
  }

  const result = await runCmd(finalCmd, timeout)
  return result
}

/**
 * AI Chatbox: translate a natural-language request into a single Kali shell
 * command. Returns { command, explanation, risk } for the operator to review
 * and approve before execution via /api/kali/exec.
 */
export async function suggestKaliCommand(message, history = []) {
  if (!message || typeof message !== 'string' || !message.trim()) {
    throw new Error('Message is required')
  }
  if (!llm.isConfigured()) {
    throw new Error('No AI provider configured — set an API key in Settings')
  }

  const ctx = history.slice(-6).map(h => `${h.role}: ${h.content}`).join('\n')
  const prompt = `${ctx ? ctx + '\n' : ''}user: ${message}

You are the command planner for a Kali Linux pentest box. Convert the user's natural-language request into ONE ready-to-run shell command.

Rules:
1. Output a SINGLE command (or a short one-line pipeline). No multi-line scripts, no interactive commands (no nano/vim/top/less), no commands requiring TTY input.
2. Prefer read-only/diagnostic commands (df, free, ss, ps, ip, ls, cat, tail, systemctl status, journalctl, docker ps, nmap -sV without exploitation flags).
3. If the request is destructive (rm, mkfs, dd, shutdown, service restart), still provide the command but set risk to "high".
4. Add sensible limits to verbose output: pipe through head/tail (e.g. "tail -n 20", "head -n 50") where appropriate.
5. If the request is impossible as one command or not security/host-related, set command to "" and explain why.

Respond ONLY with JSON:
{
  "command": "the exact shell command to run",
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

  // Reasoning models may emit thinking/prose before (or instead of) the JSON — clean aggressively
  const cleaned = String(raw)
    .replace(/<think>[\s\S]*?<\/think>/gi, '') // strip reasoning blocks
    .replace(/^```(json)?/i, '')
    .replace(/```/g, '')
    .trim()

  let parsed
  try {
    parsed = JSON.parse(cleaned)
  } catch {
    // Scan for a JSON object anywhere in the response (greedy first, then flat objects)
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
      // Last resort: look for a line that actually looks like a shell command
      const cmdLine = cleaned.split('\n').map((l) => l.trim()).find((l) => l
        && !/[.?!]$/.test(l)
        && /^(apt|apt-get|dpkg|df|free|ss|ps|ip|ifconfig|ls|cat|tail|head|systemctl|journalctl|service|docker|nmap|who|w|uname|uptime|du|id|last|netstat|crontab|grep|find|which|curl|wget|echo|date|vmstat|iostat|lsof|getent|passwd|chage|ufw|iptables|fail2ban-client)\b/.test(l))
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

  // Prefer passwordless sudo (NOPASSWD in sudoers). Falls back to config.kaliSudoPassword.
  const sudo = config.kaliSudoPassword ? `echo ${config.kaliSudoPassword} | sudo -S` : 'sudo'
  let cmd = `${sudo} systemctl ${action} ${service}`

  // msfrpcd is owned by sentinelai.service (the only unit allowed to own port
  // 55553). Addressing it through systemd keeps a single supervisor for the
  // port. The retired form killed the unit's process with `pkill -f msfrpcd`
  // and spawned an untracked `nohup` copy -- systemd then no longer knew what
  // owned 55553, and the next `systemctl restart` collided with the orphan.
  // See defect N-06 in AGENTS.md and resources/ARCHIVED-second-supervisor.md.
  if (service === 'msfrpcd') {
    if (action === 'status') {
      cmd = `systemctl is-active sentinelai; ss -lntp 2>/dev/null | grep -F ':55553' || echo 'port 55553 not listening'`
    } else {
      cmd = `${sudo} systemctl ${action} sentinelai`
    }
  }

  const result = await runCmd(cmd, 15000)
  return result
}

/** Audit all 22 Pentest Tools */
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
    const path = await checkBin(t.name)
    audited.push({
      ...t,
      installed: Boolean(path),
      path: path || null,
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

/** Trigger background installation/update of all tools */
export function triggerToolsInstall() {
  // Prefer passwordless sudo (NOPASSWD in sudoers). Falls back to config.kaliSudoPassword.
  const sudo = config.kaliSudoPassword ? `echo ${config.kaliSudoPassword} | sudo -S` : 'sudo'
  const installCmd = `
    ${sudo} apt update -y && \
    ${sudo} apt install -y nmap nikto nuclei gobuster feroxbuster sqlmap ffuf dirsearch wafw00f subfinder amass masscan sslscan whatweb wpscan hydra avahi-daemon avahi-utils libnss-mdns python3-pip httpx-toolkit && \
    (pip3 install arjun --break-system-packages 2>/dev/null || true) && \
    (go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || true) && \
    (go install github.com/hahwul/dalfox/v2@latest 2>/dev/null || true) && \
    ([ -f ~/go/bin/katana ] && ${sudo} cp ~/go/bin/katana /usr/local/bin/katana 2>/dev/null || true) && \
    ([ -f ~/go/bin/dalfox ] && ${sudo} cp ~/go/bin/dalfox /usr/local/bin/dalfox 2>/dev/null || true) && \
    (if command -v httpx-toolkit >/dev/null 2>&1; then ${sudo} ln -sf "$(which httpx-toolkit)" /usr/local/bin/httpx 2>/dev/null || true; fi)
  `

  setImmediate(async () => {
    try {
      await runCmd(installCmd, 300000)
    } catch (e) {
      console.error('[kali-control] Tools install error:', e.message)
    }
  })

  return { ok: true, message: 'Tool installation initiated in background' }
}
