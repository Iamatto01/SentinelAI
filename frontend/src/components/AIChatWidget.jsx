import React, { useEffect, useRef, useState } from 'react'
import { X, Send, Loader2, Sparkles, Trash2 } from 'lucide-react'
import InspectorLogo from './InspectorLogo.jsx'
import { api } from '../lib/api.js'
import { useScanContext } from '../lib/ScanContext.jsx'

export default function AIChatWidget() {
  const [open, setOpen] = useState(false)
  const [agent] = useState('web-hunter')
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [messages, setMessages] = useState([
    { role: 'assistant', content: 'Hi — I am SentinelAI Assistant. I can explain findings, suggest next steps, or help plan an attack path. How can I help?' },
  ])
  const endRef = useRef(null)
  const inputRef = useRef(null)
  const { currentScan } = useScanContext()

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, open])

  useEffect(() => {
    if (open) {
      setTimeout(() => inputRef.current?.focus(), 150)
    }
  }, [open])

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
    e?.preventDefault()
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

  const clearChat = () => {
    setMessages([
      { role: 'assistant', content: 'Conversation reset. How can I assist you with your penetration test or findings?' }
    ])
  }

  return (
    <>
      {/* Floating Action Button (Mobile & Desktop tuned) */}
      {!open && (
        <button
          onClick={() => setOpen(true)}
          title="SentinelAI Detective Assistant"
          aria-label="Open SentinelAI Chat"
          className="fixed bottom-4 right-4 sm:bottom-6 sm:right-6 z-40 w-13 h-13 rounded-2xl flex items-center justify-center hover:scale-110 active:scale-95 transition-all p-2 bg-slate-950/95 border border-purple-500/50 shadow-[0_0_24px_rgba(168,85,247,0.4)] hover:border-purple-400 hover:shadow-[0_0_32px_rgba(168,85,247,0.6)] cursor-pointer"
        >
          <InspectorLogo size={28} />
          <span className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-purple-500 border-2 border-slate-950 animate-pulse" />
        </button>
      )}

      {/* Mobile Backdrop Overlay (dismiss on touch) */}
      {open && (
        <div
          onClick={() => setOpen(false)}
          className="fixed inset-0 bg-slate-950/70 backdrop-blur-sm z-40 sm:hidden transition-opacity"
          aria-hidden="true"
        />
      )}

      {/* Responsive Chat Widget Window */}
      {open && (
        <div
          className="fixed inset-x-3 bottom-3 top-16 sm:inset-auto sm:bottom-6 sm:right-6 sm:w-96 sm:h-[540px] z-50 card flex flex-col overflow-hidden glass-in shadow-2xl rounded-3xl border border-purple-500/30 bg-slate-950/95 backdrop-blur-2xl"
          role="dialog"
          aria-label="AI Chat Assistant"
        >
          {/* Header Bar */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-white/10 bg-gradient-to-r from-purple-950/40 via-slate-900/60 to-slate-950 shrink-0">
            <div className="flex items-center gap-2.5 min-w-0">
              <InspectorLogo size={24} />
              <div className="min-w-0">
                <div className="flex items-center gap-1.5">
                  <p className="text-sm font-bold text-slate-100 tracking-tight truncate">AI Detective</p>
                  <span className="text-[9px] bg-purple-500/20 text-purple-300 px-2 py-0.5 rounded-full border border-purple-500/30 font-extrabold uppercase">
                    web-hunter
                  </span>
                </div>
                <p className="text-[10px] text-slate-400 truncate flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" /> Ready to assist
                </p>
              </div>
            </div>

            <div className="flex items-center gap-1">
              <button
                onClick={clearChat}
                title="Clear Chat History"
                className="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-white/5 rounded-xl transition-colors cursor-pointer"
              >
                <Trash2 size={16} />
              </button>
              <button
                onClick={() => setOpen(false)}
                title="Close Chat"
                className="p-1.5 text-slate-400 hover:text-white hover:bg-white/5 rounded-xl transition-colors cursor-pointer"
              >
                <X size={18} />
              </button>
            </div>
          </div>

          {/* Chat Message Scrollable Area */}
          <div className="flex-1 overflow-y-auto p-4 space-y-3 overscroll-contain">
            {messages.map((m, i) => (
              <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                <div
                  className={`max-w-[88%] sm:max-w-[85%] rounded-2xl px-3.5 py-2.5 text-xs sm:text-sm whitespace-pre-wrap leading-relaxed ${
                    m.role === 'user'
                      ? 'text-white font-medium shadow-md shadow-purple-950/40'
                      : 'glass-soft text-slate-200 border border-white/10 shadow-sm'
                  }`}
                  style={m.role === 'user' ? { background: 'linear-gradient(135deg, #a855f7 0%, #7c3aed 100%)' } : {}}
                >
                  {m.content}
                </div>
              </div>
            ))}
            {busy && (
              <div className="flex justify-start">
                <div className="glass-soft rounded-2xl px-3.5 py-2 flex items-center gap-2 border border-purple-500/20">
                  <Loader2 size={14} className="animate-spin text-purple-400" />
                  <span className="text-xs text-purple-300 font-medium">Analysing threat telemetry…</span>
                </div>
              </div>
            )}
            <div ref={endRef} />
          </div>

          {/* Context Quick-Prompts (if current scan present) */}
          {currentScan?.scan && (
            <div className="px-3 py-2 border-t border-white/5 bg-slate-900/40 flex flex-wrap gap-1.5 shrink-0">
              <button
                type="button"
                onClick={() => { setInput('List all crawl findings and vulnerabilities from this scan'); }}
                className="text-[10px] text-purple-200 hover:text-white bg-purple-500/15 hover:bg-purple-500/25 rounded-lg px-2.5 py-1 border border-purple-500/30 transition-all font-semibold cursor-pointer"
              >
                List scan findings
              </button>
              <button
                type="button"
                onClick={() => { setInput('What is the risk score and critical flaw breakdown?'); }}
                className="text-[10px] text-purple-200 hover:text-white bg-purple-500/15 hover:bg-purple-500/25 rounded-lg px-2.5 py-1 border border-purple-500/30 transition-all font-semibold cursor-pointer"
              >
                Risk summary
              </button>
            </div>
          )}

          {/* Message Input Bar */}
          <form onSubmit={send} className="p-3 border-t border-white/10 bg-slate-950 flex items-center gap-2 shrink-0">
            <input
              ref={inputRef}
              className="input flex-1 text-xs sm:text-sm py-2.5 px-3 rounded-xl border border-white/15 focus:border-purple-500 focus:ring-1 focus:ring-purple-500/40 bg-slate-900/80 text-white placeholder-slate-500"
              placeholder="Ask the AI specialist…"
              value={input}
              onChange={(e) => setInput(e.target.value)}
            />
            <button
              type="submit"
              disabled={busy || !input.trim()}
              className="btn-primary px-3.5 py-2.5 rounded-xl shadow-[0_0_12px_rgba(168,85,247,0.3)] disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer flex items-center justify-center shrink-0"
              aria-label="Send Message"
            >
              <Send size={15} />
            </button>
          </form>
        </div>
      )}
    </>
  )
}
