import React, { useEffect, useRef, useState } from 'react'
import { X, Send, Loader2 } from 'lucide-react'
import InspectorLogo from './InspectorLogo.jsx'
import { api } from '../lib/api.js'
import { useScanContext } from '../lib/ScanContext.jsx'

export default function AIChatWidget() {
  const [open, setOpen] = useState(false)
  const [agent] = useState('web-hunter')
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [messages, setMessages] = useState([
    { role: 'assistant', content: 'Hi — I can explain findings, suggest next steps, or help plan an attack path. Pick a specialist and ask.' },
  ])
  const endRef = useRef(null)
  const { currentScan } = useScanContext()

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [messages, open])

  // When scan context changes, inject a contextual note into the conversation
  useEffect(() => {
    if (currentScan && currentScan.scan) {
      const scan = currentScan.scan
      const findingCount = currentScan.findings?.length || 0
      const note = `📋 **Context: Scan "${scan.target}"** — ${scan.mode} scan, status: ${scan.status}, ${findingCount} findings detected. I can reference these findings in my responses.`
      setMessages((prev) => {
        // Avoid duplicate context messages
        if (prev.some((m) => m.role === 'system' && m.content.startsWith('📋'))) return prev
        return [...prev, { role: 'assistant', content: note }]
      })
    }
  }, [currentScan])

  async function send(e) {
    e.preventDefault()
    const text = input.trim()
    if (!text || busy) return
    const next = [...messages, { role: 'user', content: text }]
    setMessages(next)
    setInput('')
    setBusy(true)
    try {
      const history = next.slice(-8).map((m) => ({ role: m.role, content: m.content }))
      let prompt = text
      // Inject scan context into the prompt if available
      if (currentScan && currentScan.scan) {
        const scan = currentScan.scan
        const findingsSummary = (currentScan.findings || []).map((f) => ({
          id: f.id,
          title: f.title,
          severity: f.severity,
          status: f.status,
          module: f.module,
          cwe_id: f.cwe_id,
        }))
        prompt = `[Scan Context: target="${scan.target}", mode="${scan.mode}", status="${scan.status}", risk_score="${scan.risk_score}"]\n\nFindings (${findingsSummary.length} total):\n${JSON.stringify(findingsSummary, null, 2)}\n\nUser Question: ${text}`
      }
      const res = await api.agentChat(prompt, agent, history)
      setMessages((p) => [...p, { role: 'assistant', content: res.reply || '(no reply)' }])
    } catch (err) {
      setMessages((p) => [...p, { role: 'assistant', content: `Error: ${err.message}` }])
    }
    setBusy(false)
  }

  return (
    <>
      {!open && (
        <button onClick={() => setOpen(true)} title="AI assistant"
          className="fixed bottom-6 right-6 z-50 h-13 w-13 rounded-full shadow-glow grid place-items-center hover:scale-105 transition-transform p-2 bg-slate-900 border border-red-500/40">
          <InspectorLogo size={28} />
        </button>
      )}
      {open && (
        <div className="fixed bottom-6 right-6 z-50 w-full max-w-sm h-[540px] card flex flex-col overflow-hidden glass-in">
          <div className="flex items-center justify-between px-4 py-3 border-b border-white/10">
            <div className="flex items-center gap-2">
              <InspectorLogo size={22} />
              <p className="text-sm font-semibold text-slate-100">AI Assistant</p>
              <span className="text-[10px] bg-accent/10 text-accent px-2 py-0.5 rounded-full border border-accent/20">web-hunter</span>
            </div>
            <div className="flex items-center gap-2">
              <button onClick={() => setOpen(false)} className="text-slate-500 hover:text-slate-200"><X size={18} /></button>
            </div>
          </div>
          <div className="flex-1 overflow-y-auto p-4 space-y-3">
            {messages.map((m, i) => (
              <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                <div className={`max-w-[85%] rounded-2xl px-3.5 py-2 text-sm whitespace-pre-wrap ${m.role === 'user' ? 'text-ink-950' : 'glass-soft text-slate-200'}`}
                  style={m.role === 'user' ? { background: 'linear-gradient(135deg, #22d3ee, #67e8f9)' } : {}}>
                  {m.content}
                </div>
              </div>
            ))}
            {busy && <div className="flex justify-start"><div className="glass-soft rounded-2xl px-3 py-2"><Loader2 size={15} className="animate-spin text-accent" /></div></div>}
            <div ref={endRef} />
          </div>
          <form onSubmit={send} className="p-3 border-t border-white/10 flex gap-2">
            <input className="input flex-1" placeholder="Ask the specialist…" value={input} onChange={(e) => setInput(e.target.value)} />
            <button type="submit" disabled={busy} className="btn-primary px-3"><Send size={16} /></button>
          </form>
          {currentScan?.scan && (
            <div className="px-3 pb-3 flex flex-wrap gap-1.5">
              <button
                onClick={() => { setInput('List all crawl findings from this scan'); setOpen(true) }}
                className="text-[10px] text-slate-400 hover:text-slate-200 bg-ink-800/60 rounded-lg px-2.5 py-1 border border-slate-800/60"
              >
                List crawl findings
              </button>
              <button
                onClick={() => { setInput('What is the risk score and severity breakdown for this scan?'); setOpen(true) }}
                className="text-[10px] text-slate-400 hover:text-slate-200 bg-ink-800/60 rounded-lg px-2.5 py-1 border border-slate-800/60"
              >
                Risk summary
              </button>
            </div>
          )}
        </div>
      )}
    </>
  )
}
