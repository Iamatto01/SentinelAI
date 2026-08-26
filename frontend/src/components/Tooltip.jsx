import React, { useState, useRef, useEffect, useCallback } from 'react'

/**
 * Glassmorphic tooltip with fade+slide-up animation.
 * Shows after 400ms hover delay. Positions above by default, auto-flips if near viewport edge.
 *
 * Usage:
 *   <Tooltip content="Delete finding">
 *     <button><Trash2 size={16} /></button>
 *   </Tooltip>
 */
export default function Tooltip({ content, children, delay = 400, placement = 'top' }) {
  const [visible, setVisible] = useState(false)
  const [coords, setCoords] = useState({ top: 0, left: 0 })
  const timerRef = useRef(null)
  const triggerRef = useRef(null)
  const tooltipRef = useRef(null)

  const show = useCallback(() => {
    timerRef.current = setTimeout(() => {
      if (!triggerRef.current) return
      const rect = triggerRef.current.getBoundingClientRect()
      const scrollY = window.scrollY
      const scrollX = window.scrollX
      // Try top placement, flip to bottom if near top edge
      let top, left
      const gap = 8
      if (placement === 'top' || rect.top > 60) {
        top = rect.top + scrollY - gap
        left = rect.left + scrollX + rect.width / 2
      } else {
        top = rect.bottom + scrollY + gap
        left = rect.left + scrollX + rect.width / 2
      }
      setCoords({ top, left, flip: rect.top <= 60 })
      setVisible(true)
    }, delay)
  }, [delay, placement])

  const hide = useCallback(() => {
    clearTimeout(timerRef.current)
    setVisible(false)
  }, [])

  useEffect(() => () => clearTimeout(timerRef.current), [])

  if (!content) return <>{children}</>

  return (
    <>
      <span
        ref={triggerRef}
        onMouseEnter={show}
        onMouseLeave={hide}
        onFocus={show}
        onBlur={hide}
        className="inline-flex"
        style={{ position: 'relative' }}
      >
        {children}
      </span>

      {visible && (
        <div
          ref={tooltipRef}
          role="tooltip"
          className="tooltip-popup"
          style={{
            position: 'fixed',
            top: coords.top,
            left: coords.left,
            transform: coords.flip
              ? 'translate(-50%, 0)'
              : 'translate(-50%, -100%)',
            zIndex: 9999,
            pointerEvents: 'none',
          }}
        >
          {content}
        </div>
      )}
    </>
  )
}

/**
 * Convenience wrapper for icon-only action buttons.
 * Adds tooltip + standard hover styling.
 */
export function IconBtn({ tooltip, onClick, disabled, className = '', children, ...rest }) {
  return (
    <Tooltip content={tooltip}>
      <button
        onClick={onClick}
        disabled={disabled}
        className={`icon-btn ${className}`}
        aria-label={tooltip}
        {...rest}
      >
        {children}
      </button>
    </Tooltip>
  )
}
