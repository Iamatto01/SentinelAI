import React, { useEffect, useState, useRef } from 'react'
import {
  Terminal as TerminalIcon,
  Cpu,
  HardDrive,
  Activity,
  Server,
  RefreshCw,
  Play,
  RotateCcw,
  CheckCircle2,
  AlertCircle,
  Clock,
  Shield,
  Wifi,
  Copy,
  Check,
  Send,
  Loader2,
  Trash2,
  DownloadCloud,
  Layers,
  Zap,
  Bot,
} from 'lucide-react'
import { api } from '../lib/api.js'

export default function KaliControl() {
  const [sysInfo, setSysInfo] = useState(null)
  const [toolsData, setToolsData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [serviceBusy, setServiceBusy] = useState(null)
  const [toolsInstalling, setToolsInstalling] = useState(false)
  const [copiedIface, setCopiedIface] = useState(null)

  // Terminal state
  const [command, setCommand] = useState('')
  const [termBusy, setTermBusy] = useState(false)
  const [history, setHistory] = useState([
    { type: 'sys', text: '=== Kali Linux Remote Control Console Initialized ===' },
    { type: 'sys', text: 'Type a shell command below or click a preset button to execute directly on the Kali host.' },
  ])
  const termContainerRef = useRef(null)

  // AI chatbox state
  const [aiInput, setAiInput] = useState('')
  const [aiBusy, setAiBusy] = useState(false)
  const [aiMessages, setAiMessages] = useState([
    { role: 'assistant', text: 'Hi! Tell me what you want to do on this Kali box in plain English (e.g. "check latest storage usage") and I will draft the command for you to review and run.' },
  ])
  const [pendingCmd, setPendingCmd] = useState(null) // { command, explanation, risk }
  const aiChatRef = useRef(null)

  useEffect(() => {
    loadData()
    const interval = setInterval(loadSysInfo, 10000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    if (termContainerRef.current) {
      termContainerRef.current.scrollTop = termContainerRef.current.scrollHeight
    }
  }, [history])

  useEffect(() => {
    if (aiChatRef.current) {
      aiChatRef.current.scrollTop = aiChatRef.current.scrollHeight
    }
  }, [aiMessages, pendingCmd, aiBusy])

  async function loadData() {
    setLoading(true)
    await Promise.all([loadSysInfo(), loadTools()])
    setLoading(false)
  }

  async function loadSysInfo() {
    try {
      const data = await api.kaliSystemInfo()
      setSysInfo(data)
    } catch (e) {
      console.error('Failed to load system info:', e)
    }
  }

  async function loadTools() {
    try {
      const data = await api.kaliTools()
      setToolsData(data)
    } catch (e) {
      console.error('Failed to load tools audit:', e)
    }
  }

  async function handleServiceAction(service, action) {
    setServiceBusy(`${service}-${action}`)
    try {
      await api.kaliServiceAction(service, action)
      setHistory((prev) => [
        ...prev,
        { type: 'sys', text: `[service] Executed ${action} on ${service}` },
      ])
      await loadSysInfo()
    } catch (e) {
      setHistory((prev) => [
        ...prev,
        { type: 'err', text: `[service-error] ${service} ${action} failed: ${e.message}` },
      ])
    } finally {
      setServiceBusy(null)
    }
  }

  async function handleExec(cmdToRun) {
    const cmd = (cmdToRun || command).trim()
    if (!cmd) return
    setCommand('')
    setTermBusy(true)

    setHistory((prev) => [...prev, { type: 'cmd', text: `$ ${cmd}` }])

    try {
      const res = await api.kaliExec(cmd)
      if (res.stdout) {
        setHistory((prev) => [...prev, { type: 'out', text: res.stdout }])
      }
      if (res.stderr) {
        setHistory((prev) => [...prev, { type: 'err', text: res.stderr }])
      }
      if (!res.stdout && !res.stderr) {
        setHistory((prev) => [...prev, { type: 'sys', text: `(Command completed with exit code ${res.code})` }])
      }
    } catch (e) {
      setHistory((prev) => [...prev, { type: 'err', text: `Error: ${e.message}` }])
    } finally {
      setTermBusy(false)
    }
  }

  // ── AI Chatbox handlers ──
  async function handleAiAsk(e) {
    e.preventDefault()
    const msg = aiInput.trim()
    if (!msg || aiBusy) return
    setAiInput('')
    setAiBusy(true)
    setPendingCmd(null)
    setAiMessages((prev) => [...prev, { role: 'user', text: msg }])

    try {
      const convoHistory = aiMessages
        .filter((m) => m.text)
        .slice(-6)
        .map((m) => ({ role: m.role, content: m.text }))
      const suggestion = await api.kaliSuggest(msg, convoHistory)
      setPendingCmd(suggestion)
      setAiMessages((prev) => [
        ...prev,
        { role: 'assistant', text: suggestion.explanation || 'Here is the command I suggest:' },
      ])
    } catch (e2) {
      setAiMessages((prev) => [...prev, { role: 'assistant', text: `⚠ ${e2.message}`, error: true }])
    } finally {
      setAiBusy(false)
    }
  }

  async function handleRunSuggested() {
    if (!pendingCmd || termBusy) return
    setAiMessages((prev) => [...prev, { role: 'assistant', text: `▶ Running: ${pendingCmd.command}` }])
    setPendingCmd(null)
    await handleExec(pendingCmd.command)
  }

  function handleDiscardSuggested() {
    if (!pendingCmd) return
    setAiMessages((prev) => [...prev, { role: 'assistant', text: `✕ Discarded: ${pendingCmd.command}` }])
    setPendingCmd(null)
  }

  async function handleInstallAllTools() {
    if (!window.confirm('This will run apt update and install/update all 22 security pentest tools in the background. Continue?')) return
    setToolsInstalling(true)
    try {
      await api.kaliToolsInstall()
      setHistory((prev) => [
        ...prev,
        { type: 'sys', text: '[tools] Tool installation triggered in background (apt update + install). Check terminal or audit in 1-2 mins.' },
      ])
      setTimeout(loadTools, 5000)
    } catch (e) {
      alert(`Install trigger failed: ${e.message}`)
    } finally {
      setTimeout(() => setToolsInstalling(false), 8000)
    }
  }

  function copyText(txt, key) {
    navigator.clipboard.writeText(txt)
    setCopiedIface(key)
    setTimeout(() => setCopiedIface(null), 2000)
  }

  function formatUptime(sec) {
    if (!sec) return 'N/A'
    const days = Math.floor(sec / 86400)
    const hours = Math.floor((sec % 86400) / 3600)
    const mins = Math.floor((sec % 3600) / 60)
    return `${days}d ${hours}h ${mins}m`
  }

  const presets = [
    { label: 'Storage & Disks', cmd: 'df -h && echo "" && lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,LABEL' },
    { label: 'Top Processes (htop)', cmd: 'htop' },
    { label: 'Memory & Swap', cmd: 'free -h' },
    { label: 'Check IP Addresses', cmd: 'ip -br addr show' },
    { label: 'PM2 Status', cmd: 'pm2 list 2>/dev/null || echo "PM2 not active"' },
    { label: 'Running Scan Processes', cmd: 'ps aux | grep -E "nmap|nuclei|sqlmap|ffuf|nikto|msf" | grep -v grep' },
    { label: 'Hexstrike Logs (Last 20)', cmd: 'tail -n 20 /home/kali/hexstrike.log 2>/dev/null || echo "No hexstrike log"' },
    { label: 'SentinelAI Logs (Last 20)', cmd: 'tail -n 20 /home/kali/sentinelai.log 2>/dev/null || echo "No sentinelai log"' },
    { label: 'Metasploit RPC Status', cmd: 'ss -tlnp | grep 55553' },
    { label: 'Nmap & Nuclei Version', cmd: 'nmap -V && nuclei -version' },
    { label: 'Recheck DNS & Tunnel', cmd: 'curl -sI https://sentinelai.studio | head -n 3' },
  ]

  if (loading && !sysInfo) {
    return (
      <div className="flex flex-col items-center justify-center py-24 space-y-3">
        <Loader2 className="animate-spin text-cyan-400" size={36} />
        <span className="text-sm font-bold text-slate-300">Connecting to Kali Linux Server...</span>
      </div>
    )
  }

  return (
    <div className="space-y-6 motion-fade-up">
      {/* Header Banner */}
      <div className="card p-6 border border-white/15 bg-gradient-to-r from-slate-950/90 via-slate-900/70 to-slate-950/90 backdrop-blur-2xl relative overflow-hidden flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="absolute top-0 right-0 w-80 h-80 bg-red-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="z-10">
          <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full bg-red-500/15 border border-red-500/30 text-red-300 text-xs font-bold mb-2">
            <TerminalIcon size={14} className="text-red-400" /> Remote Host Controller
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight flex items-center gap-3">
            Kali Linux Remote Operations Center
            <span className="text-xs px-2.5 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-mono flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" /> LIVE
            </span>
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Real-time telemetry, service controller, security tools manager, and interactive Linux command terminal.
          </p>
        </div>

        <div className="flex items-center gap-3 z-10 shrink-0">
          <button
            onClick={loadData}
            className="btn-ghost text-xs py-2 px-3 flex items-center gap-1.5 hover:text-cyan-300"
          >
            <RefreshCw size={14} /> Refresh Telemetry
          </button>
        </div>
      </div>

      {/* System Telemetry Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Host & Kernel */}
        <div className="card p-5 border border-white/10 space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-bold uppercase tracking-wider">Host Node</span>
            <Server size={18} className="text-cyan-400" />
          </div>
          <div className="font-extrabold text-lg text-white font-mono truncate">{sysInfo?.hostname || 'kali'}</div>
          <div className="text-[11px] text-slate-400 font-mono truncate">
            {sysInfo?.platform} {sysInfo?.arch} • {sysInfo?.release}
          </div>
        </div>

        {/* CPU & Load */}
        <div className="card p-5 border border-white/10 space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-bold uppercase tracking-wider">CPU Cores & Load</span>
            <Cpu size={18} className="text-purple-400" />
          </div>
          <div className="font-extrabold text-lg text-white font-mono">
            {sysInfo?.cpuCount} Cores
          </div>
          <div className="text-[11px] text-slate-400 font-mono">
            Load: {sysInfo?.loadAvg?.map((l) => l.toFixed(2)).join(', ') || '0.00'}
          </div>
        </div>

        {/* RAM Usage */}
        <div className="card p-5 border border-white/10 space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-bold uppercase tracking-wider">Memory RAM</span>
            <Activity size={18} className="text-amber-400" />
          </div>
          <div className="font-extrabold text-lg text-white font-mono flex items-center justify-between">
            <span>{sysInfo?.memory?.usedMb || 0} MB</span>
            <span className="text-xs font-bold text-slate-400">/ {sysInfo?.memory?.totalMb || 0} MB</span>
          </div>
          <div className="w-full bg-slate-900 rounded-full h-1.5 overflow-hidden">
            <div
              className="bg-amber-400 h-1.5 rounded-full transition-all"
              style={{ width: `${Math.min(100, sysInfo?.memory?.percent || 0)}%` }}
            />
          </div>
        </div>

        {/* Disk & Uptime */}
        <div className="card p-5 border border-white/10 space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-bold uppercase tracking-wider">Disk & Uptime</span>
            <HardDrive size={18} className="text-emerald-400" />
          </div>
          <div className="font-extrabold text-lg text-white font-mono flex items-center justify-between">
            <span>{sysInfo?.disk?.used || '0G'} / {sysInfo?.disk?.total || '0G'}</span>
            <span className="text-xs font-bold text-emerald-400">{sysInfo?.disk?.percent || '0%'}</span>
          </div>
          <div className="text-[11px] text-slate-400 font-mono flex items-center gap-1">
            <Clock size={12} /> Uptime: {formatUptime(sysInfo?.uptimeSec)}
          </div>
        </div>
      </div>

      {/* Network Addresses & Connectivity Notice */}
      <div className="card p-5 border border-cyan-500/20 bg-slate-950/60 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-white/10 pb-3">
          <div className="flex items-center gap-2 text-white font-bold text-sm">
            <Wifi size={16} className="text-cyan-400" />
            <span>Active Network Interfaces & Global URLs</span>
          </div>
          <div className="text-xs text-slate-400 font-mono">
            mDNS Host: <span className="text-cyan-300 font-bold">kali.local</span>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 text-xs">
          {sysInfo?.networkIps?.map((net, idx) => (
            <div
              key={idx}
              className="p-3 rounded-xl bg-slate-900/80 border border-white/10 flex items-center justify-between"
            >
              <div>
                <span className="text-[10px] uppercase font-bold text-slate-400 block">{net.iface}</span>
                <span className="font-mono text-cyan-300 font-bold text-sm">{net.address}</span>
              </div>
              <button
                onClick={() => copyText(net.address, net.iface)}
                className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-300 hover:text-white transition-colors"
                title="Copy IP"
              >
                {copiedIface === net.iface ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
              </button>
            </div>
          ))}

          {/* Cloudflare Tunnel Public Card */}
          <div className="p-3 rounded-xl bg-gradient-to-r from-cyan-950/40 to-slate-900/80 border border-cyan-500/30 flex items-center justify-between">
            <div>
              <span className="text-[10px] uppercase font-bold text-cyan-300 block">Cloudflare Tunnel (Public)</span>
              <a
                href="https://sentinelai.studio"
                target="_blank"
                rel="noreferrer"
                className="font-mono text-white font-bold hover:underline"
              >
                sentinelai.studio
              </a>
            </div>
            <button
              onClick={() => copyText('https://sentinelai.studio', 'cf')}
              className="p-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 transition-colors"
              title="Copy URL"
            >
              {copiedIface === 'cf' ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
            </button>
          </div>
        </div>
      </div>

      {/* Services Controller & Security Tools Matrix */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Services Management (1 col) */}
        <div className="card p-5 border border-white/15 bg-slate-950/80 space-y-4">
          <div className="flex items-center justify-between border-b border-white/10 pb-3">
            <h3 className="font-bold text-white text-sm flex items-center gap-2">
              <Layers size={16} className="text-purple-400" /> Core System Services
            </h3>
            <span className="text-[10px] font-mono text-slate-400">One-click Controls</span>
          </div>

          <div className="space-y-3 text-xs">
            {/* SentinelAI */}
            <div className="p-3 rounded-xl bg-slate-900/70 border border-white/10 space-y-2">
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-bold text-white">SentinelAI Service</div>
                  <div className="text-[11px] text-slate-400 font-mono">Port 5000 / 5173</div>
                </div>
                <span className={`chip ${sysInfo?.services?.sentinelai?.active ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' : 'bg-rose-500/20 text-rose-300 border-rose-500/40'}`}>
                  {sysInfo?.services?.sentinelai?.active ? 'Active' : 'Stopped'}
                </span>
              </div>
              <div className="flex items-center gap-2 pt-1 border-t border-white/5">
                <button
                  onClick={() => handleServiceAction('sentinelai', 'restart')}
                  disabled={serviceBusy === 'sentinelai-restart'}
                  className="btn-ghost text-[11px] py-1 px-2.5 flex-1 justify-center"
                >
                  {serviceBusy === 'sentinelai-restart' ? <Loader2 size={12} className="animate-spin" /> : <RotateCcw size={12} />} Restart
                </button>
              </div>
            </div>

            {/* Hexstrike Engine */}
            <div className="p-3 rounded-xl bg-slate-900/70 border border-white/10 space-y-2">
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-bold text-white">Hexstrike REST Engine</div>
                  <div className="text-[11px] text-slate-400 font-mono">Port 8888 (150+ Tools)</div>
                </div>
                <span className={`chip ${sysInfo?.services?.hexstrike?.active ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' : 'bg-rose-500/20 text-rose-300 border-rose-500/40'}`}>
                  {sysInfo?.services?.hexstrike?.active ? 'Active' : 'Stopped'}
                </span>
              </div>
              <div className="flex items-center gap-2 pt-1 border-t border-white/5">
                <button
                  onClick={() => handleServiceAction('hexstrike', 'restart')}
                  disabled={serviceBusy === 'hexstrike-restart'}
                  className="btn-ghost text-[11px] py-1 px-2.5 flex-1 justify-center"
                >
                  {serviceBusy === 'hexstrike-restart' ? <Loader2 size={12} className="animate-spin" /> : <RotateCcw size={12} />} Restart
                </button>
              </div>
            </div>

            {/* Metasploit RPC */}
            <div className="p-3 rounded-xl bg-slate-900/70 border border-white/10 space-y-2">
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-bold text-white">Metasploit RPC (msfrpcd)</div>
                  <div className="text-[11px] text-slate-400 font-mono">Port 55553 (Exploitation)</div>
                </div>
                <span className={`chip ${sysInfo?.services?.msfrpcd?.active ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' : 'bg-rose-500/20 text-rose-300 border-rose-500/40'}`}>
                  {sysInfo?.services?.msfrpcd?.active ? 'Active' : 'Stopped'}
                </span>
              </div>
              <div className="flex items-center gap-2 pt-1 border-t border-white/5">
                <button
                  onClick={() => handleServiceAction('msfrpcd', 'restart')}
                  disabled={serviceBusy === 'msfrpcd-restart'}
                  className="btn-ghost text-[11px] py-1 px-2.5 flex-1 justify-center"
                >
                  {serviceBusy === 'msfrpcd-restart' ? <Loader2 size={12} className="animate-spin" /> : <RotateCcw size={12} />} Restart
                </button>
              </div>
            </div>

            {/* Avahi mDNS Daemon */}
            <div className="p-3 rounded-xl bg-slate-900/70 border border-white/10 space-y-2">
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-bold text-white">Avahi mDNS (kali.local)</div>
                  <div className="text-[11px] text-slate-400 font-mono">Auto-resolves on any WiFi</div>
                </div>
                <span className={`chip ${sysInfo?.services?.avahi?.active ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' : 'bg-rose-500/20 text-rose-300 border-rose-500/40'}`}>
                  {sysInfo?.services?.avahi?.active ? 'Active' : 'Stopped'}
                </span>
              </div>
              <div className="flex items-center gap-2 pt-1 border-t border-white/5">
                <button
                  onClick={() => handleServiceAction('avahi-daemon', 'restart')}
                  disabled={serviceBusy === 'avahi-daemon-restart'}
                  className="btn-ghost text-[11px] py-1 px-2.5 flex-1 justify-center"
                >
                  {serviceBusy === 'avahi-daemon-restart' ? <Loader2 size={12} className="animate-spin" /> : <RotateCcw size={12} />} Restart
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Interactive Terminal & Command Runner (2 cols) */}
        <div className="lg:col-span-2 card p-5 border border-white/15 bg-slate-950/80 flex flex-col justify-between space-y-4">
          <div className="flex items-center justify-between border-b border-white/10 pb-3">
            <div className="flex items-center gap-2 text-white font-bold text-sm">
              <TerminalIcon size={16} className="text-cyan-400" />
              <span>Interactive Kali Linux Web Terminal</span>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setHistory([])}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-white/5 transition-colors"
                title="Clear Terminal Output"
              >
                <Trash2 size={14} />
              </button>
            </div>
          </div>

          {/* Quick Presets */}
          <div className="space-y-1.5">
            <span className="text-[10px] uppercase font-bold text-slate-400 block">Quick Presets:</span>
            <div className="flex flex-wrap gap-1.5">
              {presets.map((p, idx) => (
                <button
                  key={idx}
                  onClick={() => handleExec(p.cmd)}
                  disabled={termBusy}
                  className="text-[11px] px-2.5 py-1 rounded-lg bg-white/5 border border-white/10 hover:border-cyan-400/40 hover:text-cyan-300 text-slate-300 font-mono transition-colors disabled:opacity-50 cursor-pointer"
                >
                  {p.label}
                </button>
              ))}
            </div>
          </div>

          {/* Terminal Output Window */}
          <div ref={termContainerRef} className="terminal h-72 overflow-y-auto bg-slate-950 border border-cyan-500/20 rounded-xl p-4 font-mono text-xs space-y-1.5 select-text">
            {history.map((item, idx) => (
              <div key={idx} className="leading-relaxed break-words whitespace-pre-wrap">
                {item.type === 'cmd' && <span className="text-cyan-300 font-bold">{item.text}</span>}
                {item.type === 'out' && <span className="text-slate-200">{item.text}</span>}
                {item.type === 'err' && <span className="text-rose-400 font-semibold">{item.text}</span>}
                {item.type === 'sys' && <span className="text-amber-400/90 italic">{item.text}</span>}
              </div>
            ))}
            {termBusy && (
              <div className="text-cyan-400 flex items-center gap-2 animate-pulse pt-1">
                <Loader2 size={14} className="animate-spin" /> Executing command on Kali host...
              </div>
            )}
          </div>

          {/* Command Input Bar */}
          <form
            onSubmit={(e) => {
              e.preventDefault()
              handleExec()
            }}
            className="flex items-center gap-2 pt-2"
          >
            <div className="relative flex-1">
              <span className="absolute left-3.5 top-1/2 -translate-y-1/2 font-mono text-cyan-400 text-sm font-bold">
                $
              </span>
              <input
                type="text"
                value={command}
                onChange={(e) => setCommand(e.target.value)}
                placeholder="Enter Kali shell command (e.g. nmap --version, ip a, whoami)..."
                disabled={termBusy}
                className="input pl-8 font-mono text-xs"
              />
            </div>
            <button
              type="submit"
              disabled={termBusy || !command.trim()}
              className="btn-primary text-xs py-2.5 px-4 shadow-glow flex items-center gap-1.5"
            >
              {termBusy ? <Loader2 size={14} className="animate-spin" /> : <Send size={14} />} Run
            </button>
          </form>
        </div>
      </div>

      {/* AI Command Chatbox */}
      <div className="card p-5 border border-cyan-500/25 bg-slate-950/80 space-y-4">
        <div className="flex items-center justify-between border-b border-white/10 pb-3">
          <h3 className="font-bold text-white text-sm flex items-center gap-2">
            <Bot size={16} className="text-cyan-400" /> AI Command Assistant
          </h3>
          <span className="text-[10px] font-mono text-slate-400">Natural language → command → review → run</span>
        </div>

        {/* Chat messages */}
        <div ref={aiChatRef} className="h-56 overflow-y-auto space-y-2.5 pr-1">
          {aiMessages.map((m, idx) => (
            <div key={idx} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
              <div
                className={`max-w-[85%] px-3.5 py-2 rounded-2xl text-xs leading-relaxed ${
                  m.role === 'user'
                    ? 'bg-cyan-500/20 border border-cyan-400/30 text-cyan-50 rounded-br-sm'
                    : m.error
                      ? 'bg-rose-500/10 border border-rose-500/30 text-rose-200 rounded-bl-sm'
                      : 'bg-slate-900/80 border border-white/10 text-slate-200 rounded-bl-sm'
                }`}
              >
                {m.text}
              </div>
            </div>
          ))}

          {aiBusy && (
            <div className="flex justify-start">
              <div className="bg-slate-900/80 border border-white/10 text-slate-300 px-3.5 py-2 rounded-2xl rounded-bl-sm text-xs flex items-center gap-2">
                <Loader2 size={12} className="animate-spin text-cyan-400" /> Thinking of the right command...
              </div>
            </div>
          )}

          {/* Pending command preview card */}
          {pendingCmd && (
            <div className="flex justify-start">
              <div className="max-w-[92%] w-full rounded-2xl rounded-bl-sm border border-cyan-400/40 bg-cyan-950/30 overflow-hidden">
                <div className="px-3.5 pt-2.5 pb-2 flex items-center justify-between gap-2">
                  <span className="text-[10px] uppercase font-bold text-cyan-300 tracking-wider">Proposed Command</span>
                  <span
                    className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                      pendingCmd.risk === 'high'
                        ? 'bg-rose-500/15 text-rose-300 border-rose-500/40'
                        : pendingCmd.risk === 'medium'
                          ? 'bg-amber-500/15 text-amber-300 border-amber-500/40'
                          : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40'
                    }`}
                  >
                    risk: {pendingCmd.risk}
                  </span>
                </div>
                <div className="mx-3.5 mb-2.5 bg-slate-950 border border-white/10 rounded-lg px-3 py-2 font-mono text-xs text-cyan-200 break-all select-text">
                  $ {pendingCmd.command}
                </div>
                <div className="flex items-center gap-2 px-3.5 pb-3">
                  <button
                    onClick={handleRunSuggested}
                    disabled={termBusy}
                    className="btn-primary text-[11px] py-1.5 px-3.5 flex items-center gap-1.5"
                  >
                    {termBusy ? <Loader2 size={12} className="animate-spin" /> : <Play size={12} />} Run on Kali
                  </button>
                  <button onClick={handleDiscardSuggested} className="btn-ghost text-[11px] py-1.5 px-3.5">
                    Discard
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Input */}
        <form onSubmit={handleAiAsk} className="flex items-center gap-2 pt-1">
          <input
            type="text"
            value={aiInput}
            onChange={(e) => setAiInput(e.target.value)}
            placeholder='Ask in plain English (e.g. "check latest storage usage")...'
            disabled={aiBusy}
            className="input flex-1 text-xs"
          />
          <button
            type="submit"
            disabled={aiBusy || !aiInput.trim()}
            className="btn-primary text-xs py-2.5 px-4 shadow-glow flex items-center gap-1.5"
          >
            {aiBusy ? <Loader2 size={14} className="animate-spin" /> : <Send size={14} />} Ask AI
          </button>
        </form>
      </div>

      {/* Security Tools Matrix */}
      <div className="card p-6 border border-white/15 bg-slate-950/80 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/10 pb-4">
          <div>
            <h3 className="font-extrabold text-white text-base flex items-center gap-2">
              <Shield size={18} className="text-cyan-400" /> Kali Security Pentest Tools Audit (22 Tools)
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Live status of automated penetration testing and vulnerability scanning tools on this server.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <span className="text-xs font-mono px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 font-bold">
              {toolsData?.installed || 0} / {toolsData?.total || 22} Ready
            </span>
            <button
              onClick={handleInstallAllTools}
              disabled={toolsInstalling}
              className="btn-primary text-xs py-2 px-3.5 shadow-glow flex items-center gap-1.5"
            >
              {toolsInstalling ? <Loader2 size={14} className="animate-spin" /> : <DownloadCloud size={14} />}
              Update / Install All Tools
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3 text-xs">
          {toolsData?.tools?.map((tool, idx) => (
            <div
              key={idx}
              className={`p-3 rounded-xl border transition-all ${
                tool.installed
                  ? 'bg-slate-900/60 border-white/10 hover:border-cyan-400/40'
                  : 'bg-rose-950/20 border-rose-500/30'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="font-bold text-white font-mono text-sm">{tool.name}</span>
                {tool.installed ? (
                  <CheckCircle2 size={15} className="text-emerald-400 shrink-0" />
                ) : (
                  <AlertCircle size={15} className="text-rose-400 shrink-0" />
                )}
              </div>
              <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">{tool.category}</span>
              <p className="text-[11px] text-slate-400 line-clamp-1">{tool.desc}</p>
              <div className="text-[10px] font-mono text-slate-400 truncate mt-2 border-t border-white/5 pt-1.5">
                {tool.path || 'Not found in PATH'}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
