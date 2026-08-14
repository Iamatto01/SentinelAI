import React, { createContext, useContext, useEffect, useState } from 'react'
import { Sparkles, Bot, X, ExternalLink, CheckCircle } from 'lucide-react'
import { api } from './api.js'

const AiContext = createContext(null)

const CHAT_STORAGE_KEY = 'sentinel_finding_ai_chats'

function loadSavedChats() {
  try {
    const raw = localStorage.getItem(CHAT_STORAGE_KEY)
    return raw ? JSON.parse(raw) : {}
  } catch {
    return {}
  }
}

function saveChats(chats) {
  try {
    localStorage.setItem(CHAT_STORAGE_KEY, JSON.stringify(chats))
  } catch {}
}

export function AiProvider({ children }) {
  const [findingChats, setFindingChats] = useState(loadSavedChats)
  const [activeTasks, setActiveTasks] = useState({}) // { [findingId]: { query, busy: true } }
  const [notifications, setNotifications] = useState([])
  const [drawerFinding, setDrawerFinding] = useState(null)
  const [activeTabOverride, setActiveTabOverride] = useState(null)

  useEffect(() => {
    saveChats(findingChats)
  }, [findingChats])

  const getFindingChat = (finding) => {
    if (!finding?.id) return []
    const existing = findingChats[finding.id]
    if (existing && existing.length > 0) return existing
    return [
      { role: 'assistant', text: `Hi! I am your AI Security Assistant. Ask me anything about this finding: "${finding.title}".` }
    ]
  }

  const sendFindingAiQuery = async (finding, query) => {
    if (!finding?.id || !query.trim()) return
    const fid = finding.id

    if (activeTasks[fid]?.busy) return

    const userMsg = { role: 'user', text: query.trim(), ts: Date.now() }
    
    // 1. Update finding chat history immediately
    setFindingChats((prev) => {
      const current = prev[fid] || [
        { role: 'assistant', text: `Hi! I am your AI Security Assistant. Ask me anything about this finding: "${finding.title}".` }
      ]
      const updated = [...current, userMsg]
      const next = { ...prev, [fid]: updated }
      saveChats(next)
      return next
    })

    // 2. Mark active task as running in background
    setActiveTasks((prev) => ({ ...prev, [fid]: { query: query.trim(), busy: true } }))

    // 3. Formulate contextual prompt
    let evidenceStr = '{}'
    try {
      evidenceStr = typeof finding.evidence === 'string' ? finding.evidence : JSON.stringify(finding.evidence || {})
    } catch {}

    const contextualPrompt = `[Finding Context: Title="${finding.title}", Severity="${finding.severity}", Tool/Module="${finding.module || 'scanner'}", Description="${finding.description || ''}", Evidence=${evidenceStr}]\n\nUser Question: ${query.trim()}`

    try {
      const res = await api.agentChat(contextualPrompt, 'web-hunter', [])
      const aiReply = res.reply || '(No reply returned)'

      // 4. Save AI response to chat history
      setFindingChats((prev) => {
        const current = prev[fid] || []
        const updated = [...current, { role: 'assistant', text: aiReply, ts: Date.now() }]
        const next = { ...prev, [fid]: updated }
        saveChats(next)
        return next
      })

      // 5. Trigger Popup Toast Notification
      const notifId = `notif_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`
      const notifItem = {
        id: notifId,
        findingId: fid,
        finding,
        title: finding.title,
        replyPreview: aiReply.length > 120 ? aiReply.slice(0, 120) + '…' : aiReply,
        ts: Date.now()
      }

      setNotifications((prev) => [notifItem, ...prev])

      // Play subtle browser notification if permitted
      if ('Notification' in window && Notification.permission === 'granted') {
        new Notification(`AI Assistant: ${finding.title}`, {
          body: aiReply.slice(0, 100),
          icon: '/favicon.svg'
        })
      }
    } catch (err) {
      const errMsg = `Error: ${err.message}`
      setFindingChats((prev) => {
        const current = prev[fid] || []
        const updated = [...current, { role: 'assistant', text: errMsg, ts: Date.now() }]
        const next = { ...prev, [fid]: updated }
        saveChats(next)
        return next
      })

      setNotifications((prev) => [
        {
          id: `notif_err_${Date.now()}`,
          findingId: fid,
          finding,
          title: finding.title,
          replyPreview: errMsg,
          isError: true,
          ts: Date.now()
        },
        ...prev
      ])
    } finally {
      setActiveTasks((prev) => {
        const next = { ...prev }
        delete next[fid]
        return next
      })
    }
  }

  const dismissNotification = (id) => {
    setNotifications((prev) => prev.filter((n) => n.id !== id))
  }

  const openFindingFromNotif = (notif) => {
    dismissNotification(notif.id)
    if (notif.finding) {
      setDrawerFinding(notif.finding)
      setActiveTabOverride('ai')
    }
  }

  return (
    <AiContext.Provider
      value={{
        findingChats,
        activeTasks,
        notifications,
        drawerFinding,
        activeTabOverride,
        setDrawerFinding,
        setActiveTabOverride,
        getFindingChat,
        sendFindingAiQuery,
        dismissNotification,
        openFindingFromNotif
      }}
    >
      {children}
      <AiToastContainer />
    </AiContext.Provider>
  )
}

export function useAi() {
  const ctx = useContext(AiContext)
  if (!ctx) throw new Error('useAi must be used within AiProvider')
  return ctx
}

function AiToastContainer() {
  const { notifications, dismissNotification, openFindingFromNotif } = useAi()

  if (!notifications.length) return null

  return (
    <div className="fixed bottom-6 left-6 z-[9999] flex flex-col gap-3 max-w-md w-full pointer-events-none">
      {notifications.map((n) => (
        <div
          key={n.id}
          className="pointer-events-auto glass-in rounded-2xl p-4 border border-cyan-500/40 shadow-glow bg-slate-900/95 backdrop-blur-2xl text-slate-100 flex flex-col gap-2 transition-all"
          style={{ background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.95), rgba(30, 41, 59, 0.95))' }}
        >
          <div className="flex items-start justify-between gap-2">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
                <Bot size={18} />
              </div>
              <div>
                <p className="text-xs font-bold text-cyan-300 uppercase tracking-wider">AI Assistant Ready</p>
                <p className="text-sm font-semibold text-slate-100 line-clamp-1">{n.title}</p>
              </div>
            </div>
            <button
              onClick={() => dismissNotification(n.id)}
              className="p-1 text-slate-400 hover:text-white rounded-lg transition-colors"
            >
              <X size={16} />
            </button>
          </div>

          <p className="text-xs text-slate-300 bg-slate-800/80 p-2.5 rounded-xl border border-white/5 line-clamp-2 leading-relaxed">
            {n.replyPreview}
          </p>

          <button
            onClick={() => openFindingFromNotif(n)}
            className="btn-primary text-xs py-1.5 px-3 w-full justify-center flex items-center gap-1.5 mt-1"
          >
            <Sparkles size={13} /> View Answer & Details
          </button>
        </div>
      ))}
    </div>
  )
}
