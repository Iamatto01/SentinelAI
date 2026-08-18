import React, { useEffect, useRef } from 'react'
import { useTheme } from '../lib/ThemeContext.jsx'

export default function AIBackgroundCanvas() {
  const { theme, activeWallpaper, blur, opacity, isStatic, isNight } = useTheme()
  const canvasRef = useRef(null)

  // Lightweight 60fps particle neural constellation (Zero shadowBlur overhead)
  useEffect(() => {
    if (isStatic && theme !== 'canvas_neural') return

    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d', { alpha: true })
    let animId
    let width = (canvas.width = window.innerWidth)
    let height = (canvas.height = window.innerHeight)

    let resizeTimer
    const handleResize = () => {
      clearTimeout(resizeTimer)
      resizeTimer = setTimeout(() => {
        if (!canvas) return
        width = canvas.width = window.innerWidth
        height = canvas.height = window.innerHeight
      }, 150)
    }
    window.addEventListener('resize', handleResize, { passive: true })

    // Optimized particle count
    const count = Math.min(28, Math.floor((width * height) / 45000))
    const particles = Array.from({ length: count }, () => ({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.3,
      vy: (Math.random() - 0.5) * 0.3,
      radius: Math.random() * 1.5 + 0.8,
      hue: Math.random() > 0.5 ? 'rgba(0, 242, 254, 0.75)' : 'rgba(168, 85, 247, 0.75)', // Fast RGBA instead of HSL
    }))

    const render = () => {
      ctx.clearRect(0, 0, width, height)

      // Move & draw particles without expensive shadowBlur
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
        ctx.fillStyle = p.hue
        ctx.fill()

        // Connect nearby nodes
        for (let j = i + 1; j < particles.length; j++) {
          const p2 = particles[j]
          const dx = p.x - p2.x
          const dy = p.y - p2.y
          const distSq = dx * dx + dy * dy // Distance squared is 10x faster than Math.sqrt

          if (distSq < 14400) { // 120px * 120px
            const alpha = (1 - distSq / 14400) * 0.2
            ctx.beginPath()
            ctx.moveTo(p.x, p.y)
            ctx.lineTo(p2.x, p2.y)
            ctx.strokeStyle = `rgba(0, 242, 254, ${alpha})`
            ctx.lineWidth = 0.7
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
      clearTimeout(resizeTimer)
    }
  }, [isStatic, theme])

  const showImage = Boolean(activeWallpaper && theme !== 'static_dark' && theme !== 'canvas_neural')

  return (
    <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden select-none will-change-transform">
      {/* Background Image Layer with Optimized Hardware-accelerated CSS */}
      {showImage && (
        <div
          className="absolute inset-0 bg-cover bg-center bg-no-repeat transition-all duration-700 ease-out transform"
          style={{
            backgroundImage: `url(${activeWallpaper})`,
            filter: `blur(${Math.min(blur, 20)}px) brightness(${isNight ? 0.85 : 1.4})`,
            opacity: isNight ? opacity / 100 : Math.min(100, opacity + 15) / 100,
            transform: 'translateZ(0)',
          }}
        />
      )}

      {/* Gradient Mask */}
      <div
        className="absolute inset-0 transition-opacity duration-500"
        style={
          isNight
            ? { background: 'linear-gradient(to bottom, rgba(6,11,38,0.80), rgba(6,11,38,0.88) 50%, rgba(6,11,38,0.96))', transform: 'translateZ(0)' }
            : { background: 'linear-gradient(to bottom, rgba(238,242,247,0.85), rgba(238,242,247,0.92) 50%, rgba(238,242,247,0.97))', transform: 'translateZ(0)' }
        }
      />

      {/* Particle Canvas Layer */}
      {(!isStatic || theme === 'canvas_neural') && (
        <canvas
          ref={canvasRef}
          className="absolute inset-0 opacity-40 mix-blend-screen"
          style={{ transform: 'translateZ(0)' }}
        />
      )}
    </div>
  )
}
