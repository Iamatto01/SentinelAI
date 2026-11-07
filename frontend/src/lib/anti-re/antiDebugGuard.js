/**
 * SentinelAI Anti-Reverse Engineering & Anti-Inspection Guard
 *
 * Implements client-side anti-debugging, inspection deterrence, and keybind
 * interception to protect platform logic, AI persona communications, and proprietary
 * workflow orchestrations from unauthorized extraction.
 */

let initialized = false
let debugInterval = null
let keyHandler = null
let contextHandler = null

export function initAntiDebugGuard(options = {}) {
  if (typeof window === 'undefined' || initialized) return
  initialized = true

  // Allow disabling during local development unless explicitly forced
  const isDev = Boolean(import.meta.env.DEV)
  const forceEnable = options.force === true
  if (isDev && !forceEnable) {
    // In local development, show subtle notification without locking DevTools
    console.info(
      '%c[SentinelAI Anti-RE]%c Development mode active — Anti-Debug traps on standby.',
      'color: #06b6d4; font-weight: bold;',
      'color: #94a3b8;'
    )
    return
  }

  // 1. Console Cloaking & Legal Warning Banner
  try {
    const bannerStyle = [
      'color: #f43f5e',
      'font-size: 14px',
      'font-weight: 800',
      'background: #09090b',
      'padding: 8px 12px',
      'border-radius: 6px',
      'border: 1px solid #f43f5e',
    ].join(';')
    const textStyle = 'color: #94a3b8; font-size: 11px; line-height: 1.5;'

    setTimeout(() => {
      console.log('%c⚠️ STOP — SENTINELAI PROPRIETARY SYSTEM', bannerStyle)
      console.log(
        '%cThis platform is protected by strict Anti-Reverse Engineering governance.\n' +
        'Decompilation, memory inspection, prompt extraction, or reverse engineering of\n' +
        'SentinelAI architecture is an infringement of intellectual property under our Terms of Service.\n' +
        'All interactions with this terminal may be logged for security auditing.',
        textStyle
      )
    }, 500)
  } catch {
    // ignore
  }

  // 2. Intercept Inspect Element & Developer Shortcuts
  keyHandler = (e) => {
    // F12
    if (e.key === 'F12' || e.keyCode === 123) {
      e.preventDefault()
      e.stopPropagation()
      return false
    }

    const isCtrlOrMeta = e.ctrlKey || e.metaKey

    // Ctrl+Shift+I / Cmd+Option+I (Inspect)
    // Ctrl+Shift+J / Cmd+Option+J (Console)
    // Ctrl+Shift+C / Cmd+Option+C (Element Picker)
    if (isCtrlOrMeta && e.shiftKey && ['I', 'i', 'J', 'j', 'C', 'c'].includes(e.key)) {
      e.preventDefault()
      e.stopPropagation()
      return false
    }

    // Ctrl+U / Cmd+U (View Source)
    if (isCtrlOrMeta && (e.key === 'U' || e.key === 'u')) {
      e.preventDefault()
      e.stopPropagation()
      return false
    }

    // Ctrl+S / Cmd+S (Save Page)
    if (isCtrlOrMeta && (e.key === 'S' || e.key === 's')) {
      e.preventDefault()
      e.stopPropagation()
      return false
    }
  }
  window.addEventListener('keydown', keyHandler, true)

  // 3. Disable Right-Click Context Menu in Production
  contextHandler = (e) => {
    // Allow context menu only inside text inputs or textareas for normal editing
    const targetTag = e.target?.tagName?.toLowerCase()
    if (targetTag === 'input' || targetTag === 'textarea') return true

    e.preventDefault()
    e.stopPropagation()
    return false
  }
  window.addEventListener('contextmenu', contextHandler, true)

  // 4. Anti-Debugging Dynamic Breakpoint Trap
  // Uses indirect function evaluation so static analyzers cannot strip the call
  const startDebuggerTrap = () => {
    const trigger = () => {
      try {
        const check = function () {
          // Window dimension heuristic: detects when a docked DevTools pane is opened
          const widthThreshold = window.outerWidth - window.innerWidth > 160
          const heightThreshold = window.outerHeight - window.innerHeight > 160
          if (widthThreshold || heightThreshold) {
            const trap = Function('debugger')
            trap()
          }
        }
        check()
      } catch {
        // ignore
      }
    }

    debugInterval = setInterval(trigger, 1500)
  }

  startDebuggerTrap()
}

export function destroyAntiDebugGuard() {
  if (typeof window === 'undefined' || !initialized) return
  if (debugInterval) {
    clearInterval(debugInterval)
    debugInterval = null
  }
  if (keyHandler) {
    window.removeEventListener('keydown', keyHandler, true)
    keyHandler = null
  }
  if (contextHandler) {
    window.removeEventListener('contextmenu', contextHandler, true)
    contextHandler = null
  }
  initialized = false
}
