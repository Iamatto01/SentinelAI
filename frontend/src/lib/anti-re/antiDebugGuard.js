/**
 * SentinelAI Client Runtime Guard
 *
 * Preserves the exported guard lifecycle API without interfering with
 * accessibility, text selection/copying, vertical-tab browsers, or docked DevTools.
 */

let initialized = false

export function initAntiDebugGuard(options = {}) {
  if (typeof window === 'undefined' || initialized) return
  initialized = true

  if (options.verbose && typeof console !== 'undefined' && typeof console.info === 'function') {
    console.info('[SentinelAI] Client runtime guard initialized (non-blocking mode).')
  }
}

export function destroyAntiDebugGuard() {
  if (typeof window === 'undefined' || !initialized) return
  initialized = false
}
