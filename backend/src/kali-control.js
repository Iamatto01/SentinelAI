import os from 'node:os'
import { spawn, exec } from 'node:child_process'
import { promisify } from 'node:util'
import { llm } from './ai/llm-client.js'

const execAsync = promisify(exec)

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

    const env = { ...process.env, PATH: `${process.env.PATH || ''}:${extra}` }
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

  // Disk usage via df -h
  let disk = { total: 'N/A', used: 'N/A', free: 'N/A', percent: 'N/A' }
  try {
    const dfRes = await runCmd('df -h / | tail -n 1', 3000)
    if (dfRes.success && dfRes.stdout) {
      const parts = dfRes.stdout.split(/\s+/)
      if (parts.length >= 5) {
        disk = {
          total: parts[1],
          used: parts[2],
          free: parts[3],
          percent: parts[4],
          mount: parts[5] || '/',
        }
      }
    }
  } catch { }

  // Check key services
  const services = {
    sentinelai: await checkService('sentinelai', 5000),
    hexstrike: await checkService('hexstrike', 8888),
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

  // Basic sanitization/warning against catastrophic system destruction
  const blocked = [':(){ :|:& };:', 'rm -rf /', 'rm -rf /*', 'mkfs', 'dd if=/dev/zero of=/dev/sda']
  for (const b of blocked) {
    if (command.trim().includes(b)) {
      throw new Error(`Dangerous command blocked: ${b}`)
    }
  }

  const result = await runCmd(command, timeout)
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
  const allowedServices = ['sentinelai', 'hexstrike', 'msfrpcd', 'cloudflared', 'avahi-daemon']
  const allowedActions = ['start', 'stop', 'restart', 'status']

  if (!allowedServices.includes(service)) {
    throw new Error(`Invalid service. Allowed: ${allowedServices.join(', ')}`)
  }
  if (!allowedActions.includes(action)) {
    throw new Error(`Invalid action. Allowed: ${allowedActions.join(', ')}`)
  }

  let cmd = `echo kali | sudo -S systemctl ${action} ${service}`

  // Special handling for Hexstrike / Metasploit if not systemd units
  if (service === 'hexstrike' && action === 'restart') {
    cmd = `pkill -f hexstrike_server.py 2>/dev/null || true; sleep 1; nohup python3 /home/kali/hexstrike-ai/hexstrike_server.py --port 8888 > /home/kali/hexstrike.log 2>&1 &`
  } else if (service === 'msfrpcd' && action === 'restart') {
    cmd = `pkill -f msfrpcd 2>/dev/null || true; sleep 1; nohup msfrpcd -U msf -P msf -a 127.0.0.1 -p 55553 -S > /home/kali/msfrpcd.log 2>&1 &`
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
    { name: 'msfconsole', category: 'Exploitation & Cracking', desc: 'Metasploit penetration framework' },
    { name: 'msfrpcd', category: 'Exploitation & Cracking', desc: 'Metasploit RPC daemon' },
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
  const installCmd = `
    echo kali | sudo -S apt update -y && \
    echo kali | sudo -S apt install -y nmap nikto nuclei gobuster feroxbuster sqlmap ffuf dirsearch wafw00f subfinder amass masscan sslscan whatweb wpscan hydra metasploit-framework avahi-daemon avahi-utils libnss-mdns python3-pip httpx-toolkit && \
    (pip3 install arjun --break-system-packages 2>/dev/null || true) && \
    (go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || true) && \
    (go install github.com/hahwul/dalfox/v2@latest 2>/dev/null || true) && \
    ([ -f ~/go/bin/katana ] && sudo cp ~/go/bin/katana /usr/local/bin/katana 2>/dev/null || true) && \
    ([ -f ~/go/bin/dalfox ] && sudo cp ~/go/bin/dalfox /usr/local/bin/dalfox 2>/dev/null || true) && \
    (if command -v httpx-toolkit >/dev/null 2>&1; then sudo ln -sf "$(which httpx-toolkit)" /usr/local/bin/httpx 2>/dev/null || true; fi)
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
