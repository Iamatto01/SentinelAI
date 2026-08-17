import React, { useEffect, useRef } from 'react'
import { useTheme } from '../lib/ThemeContext.jsx'

export default function AIBackgroundCanvas() {
  const { theme, activeWallpaper, blur, opacity, isStatic, isNight } = useTheme()
  const canvasRef = useRef(null)

  // Interactive particle neural constellation for animated mode
  useEffect(() => {
    if (isStatic && theme !== 'canvas_neural') return

    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    let animId
    let width = (canvas.width = window.innerWidth)
    let height = (canvas.height = window.innerHeight)

    const handleResize = () => {
      if (!canvas) return
      width = canvas.width = window.innerWidth
      height = canvas.height = window.innerHeight
    }
    window.addEventListener('resize', handleResize)

    // Particle nodes
    const count = Math.min(45, Math.floor((width * height) / 30000))
    const particles = Array.from({ length: count }, () => ({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.4,
      vy: (Math.random() - 0.5) * 0.4,
      radius: Math.random() * 1.8 + 1,
      hue: Math.random() > 0.5 ? 185 : 275, // Cyan & Purple
    }))

    const render = () => {
      ctx.clearRect(0, 0, width, height)

      // Move & draw particles
      for (let i = 0; i < particles.length; i++) {
        const p = particles[i]
        p.x += p.vx
        p.y += p.vy

        if (p.x < 0) p.x = width
        if (p.x > width) p.x = 0
        if (p.y < 0) p.y = height
        if (p.y > height) p.y = 0

        ctx.beginPath()
        ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2)
        ctx.fillStyle = `hsla(${p.hue}, 90%, 65%, 0.6)`
        ctx.shadowBlur = 8
        ctx.shadowColor = `hsla(${p.hue}, 90%, 65%, 0.8)`
        ctx.fill()
        ctx.shadowBlur = 0

        // Connect nearby nodes
        for (let j = i + 1; j < particles.length; j++) {
          const p2 = particles[j]
          const dx = p.x - p2.x
          const dy = p.y - p2.y
          const dist = Math.sqrt(dx * dx + dy * dy)

          if (dist < 130) {
            ctx.beginPath()
            ctx.moveTo(p.x, p.y)
            ctx.lineTo(p2.x, p2.y)
            const alpha = (1 - dist / 130) * 0.25
            ctx.strokeStyle = `hsla(${p.hue}, 80%, 60%, ${alpha})`
            ctx.lineWidth = 0.8
            ctx.stroke()
          }
        }
      }

      animId = requestAnimationFrame(render)
    }

    render()

    return () => {
      window.removeEventListener('resize', handleResize)
      cancelAnimationFrame(animId)
    }
  }, [isStatic, theme])

  const showImage = Boolean(activeWallpaper && theme !== 'static_dark' && theme !== 'canvas_neural')

  return (
    <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden select-none">
      {/* Background Image Layer with Blur & Opacity */}
      {showImage && (
        <div
          className="absolute inset-0 bg-cover bg-center bg-no-repeat transition-all duration-1000 ease-in-out transform scale-105"
          style={{
            backgroundImage: `url(${activeWallpaper})`,
            filter: `blur(${blur}px) brightness(${isNight ? 0.85 : 1.6})`,
            opacity: isNight ? opacity / 100 : Math.min(100, opacity + 15) / 100,
          }}
        />
      )}

      {/* Gradient Mask: obsidian at night, soft white veil in day mode */}
      <div
        className="absolute inset-0 transition-all duration-700"
        style={
          isNight
            ? { background: 'linear-gradient(to bottom, rgba(6,11,38,0.75), rgba(6,11,38,0.85) 50%, rgba(6,11,38,0.95))', backdropFilter: 'saturate(150%)' }
            : { background: 'linear-gradient(to bottom, rgba(238,242,247,0.82), rgba(238,242,247,0.90) 50%, rgba(238,242,247,0.96))' }
        }
      />

      {/* Particle Canvas Layer */}
      {(!isStatic || theme === 'canvas_neural') && (
        <canvas
          ref={canvasRef}
          className="absolute inset-0 opacity-40 mix-blend-screen"
        />
      )}
    </div>
  )
}
