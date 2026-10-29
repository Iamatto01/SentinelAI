import React, { useEffect, useRef } from 'react'

/**
 * HeroNodeGraph
 * High-performance 60fps monochrome interactive node-graph representing
 * real-time attack surface discovery and endpoint mapping.
 * Reacts subtly to cursor movement with physics spring damping.
 */
export default function HeroNodeGraph() {
  const canvasRef = useRef(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d', { alpha: true })
    if (!ctx) return

    let animId
    let width = (canvas.width = canvas.parentElement?.clientWidth || window.innerWidth)
    let height = (canvas.height = canvas.parentElement?.clientHeight || 600)

    const mouse = { x: -1000, y: -1000, targetX: -1000, targetY: -1000, radius: 140 }

    const handleResize = () => {
      if (!canvas || !canvas.parentElement) return
      width = canvas.width = canvas.parentElement.clientWidth
      height = canvas.height = canvas.parentElement.clientHeight
      initNodes()
    }
    window.addEventListener('resize', handleResize)

    const handleMouseMove = (e) => {
      const rect = canvas.getBoundingClientRect()
      mouse.targetX = e.clientX - rect.left
      mouse.targetY = e.clientY - rect.top
    }

    const handleMouseLeave = () => {
      mouse.targetX = -1000
      mouse.targetY = -1000
    }

    window.addEventListener('mousemove', handleMouseMove)
    document.addEventListener('mouseleave', handleMouseLeave)

    // Node blueprint representing real-time pentest assets
    const NODE_LABELS = [
      'CORE // TARGET_ROOT',
      'API // GATEWAY',
      'PORT 443 // HTTPS',
      'PORT 80 // HTTP',
      'PORT 22 // SSH',
      'PORT 8080 // PROXY',
      'AUTH // JWT_GUARD',
      'CVE-2024-27198',
      'CWE-89 // SQLI',
      'AGENT // WEB_HUNTER',
      'AGENT // DB_ATTACKER',
      'SUBDOMAIN // STAGING',
      'SUBDOMAIN // VAULT',
      'KALI // NATIVE_DAEMON',
      'RAG // FTS5_PAYLOADS',
      'DIFF // AUTO_PATCH',
      'REPORT // PDF_AUDIT',
      'DISCORD // RELAY',
      'TELEGRAM // BOT',
      'OCTOKIT // PR_BOT'
    ]

    let nodes = []
    let packets = []

    function initNodes() {
      const count = Math.min(26, Math.max(16, Math.floor((width * height) / 28000)))
      nodes = []
      packets = []

      for (let i = 0; i < count; i++) {
        const isCore = i === 0
        const isVuln = i === 7 || i === 8
        const isAgent = i === 9 || i === 10 || i === 13

        const x = isCore ? width / 2 : Math.random() * (width - 120) + 60
        const y = isCore ? height / 2 : Math.random() * (height - 120) + 60

        nodes.push({
          id: i,
          baseX: x,
          baseY: y,
          x,
          y,
          vx: (Math.random() - 0.5) * 0.45,
          vy: (Math.random() - 0.5) * 0.45,
          radius: isCore ? 6 : isVuln ? 4.5 : isAgent ? 4 : 2.5,
          label: NODE_LABELS[i % NODE_LABELS.length],
          isCore,
          isVuln,
          isAgent,
          pulse: Math.random() * Math.PI * 2,
        })
      }

      // Initialize packets that travel between connected nodes
      for (let p = 0; p < 8; p++) {
        packets.push({
          fromIndex: Math.floor(Math.random() * nodes.length),
          toIndex: Math.floor(Math.random() * nodes.length),
          progress: Math.random(),
          speed: 0.006 + Math.random() * 0.008,
        })
      }
    }

    initNodes()

    const render = () => {
      ctx.clearRect(0, 0, width, height)

      // Smooth mouse damping
      mouse.x += (mouse.targetX - mouse.x) * 0.15
      mouse.y += (mouse.targetY - mouse.y) * 0.15

      // Update and draw connections
      const maxDistance = 150
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].x - nodes[j].x
          const dy = nodes[i].y - nodes[j].y
          const dist = Math.sqrt(dx * dx + dy * dy)

          if (dist < maxDistance) {
            const alpha = (1 - dist / maxDistance) * 0.22
            ctx.beginPath()
            ctx.moveTo(nodes[i].x, nodes[i].y)
            ctx.lineTo(nodes[j].x, nodes[j].y)
            ctx.strokeStyle = `rgba(255, 255, 255, ${alpha})`
            ctx.lineWidth = nodes[i].isCore || nodes[j].isCore ? 1.2 : 0.7
            ctx.stroke()
          }
        }
      }

      // Update & render traveling packets
      for (let k = 0; k < packets.length; k++) {
        const p = packets[k]
        p.progress += p.speed
        if (p.progress >= 1) {
          p.progress = 0
          p.fromIndex = p.toIndex
          p.toIndex = Math.floor(Math.random() * nodes.length)
        }

        const nodeA = nodes[p.fromIndex]
        const nodeB = nodes[p.toIndex]
        if (nodeA && nodeB) {
          const px = nodeA.x + (nodeB.x - nodeA.x) * p.progress
          const py = nodeA.y + (nodeB.y - nodeA.y) * p.progress

          ctx.beginPath()
          ctx.arc(px, py, 1.8, 0, Math.PI * 2)
          ctx.fillStyle = '#ffffff'
          ctx.shadowColor = 'rgba(255, 255, 255, 0.9)'
          ctx.shadowBlur = 6
          ctx.fill()
          ctx.shadowBlur = 0
        }
      }

      // Update & render nodes
      for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i]
        n.pulse += 0.035

        // Boundary bounce
        n.x += n.vx
        n.y += n.vy
        if (n.x < 30 || n.x > width - 30) n.vx *= -1
        if (n.y < 30 || n.y > height - 30) n.vy *= -1

        // Mouse interaction (repulsion & subtle magnet)
        const mdx = n.x - mouse.x
        const mdy = n.y - mouse.y
        const mdist = Math.sqrt(mdx * mdx + mdy * mdy)
        if (mdist < mouse.radius && mdist > 0) {
          const force = (1 - mdist / mouse.radius) * 1.5
          n.x += (mdx / mdist) * force * 2.2
          n.y += (mdy / mdist) * force * 2.2
        }

        // Draw pulsing outer ring for core / vulnerabilities
        if (n.isCore || n.isVuln || n.isAgent) {
          const ringRadius = n.radius + Math.sin(n.pulse) * 4 + 4
          ctx.beginPath()
          ctx.arc(n.x, n.y, Math.max(0.5, ringRadius), 0, Math.PI * 2)
          ctx.strokeStyle = n.isVuln
            ? 'rgba(255, 255, 255, 0.55)'
            : 'rgba(255, 255, 255, 0.25)'
          ctx.lineWidth = 1
          ctx.stroke()
        }

        // Draw node center
        ctx.beginPath()
        ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2)
        ctx.fillStyle = n.isCore
          ? '#ffffff'
          : n.isVuln
          ? '#ffffff'
          : n.isAgent
          ? '#e5e5e5'
          : '#888888'
        ctx.fill()

        // Monospace label on hover or key nodes
        const isHovered = mdist < 60
        if (isHovered || n.isCore || (n.isVuln && Math.sin(n.pulse) > 0.4)) {
          ctx.font = '10px "JetBrains Mono", monospace'
          ctx.fillStyle = isHovered ? '#ffffff' : 'rgba(255, 255, 255, 0.7)'
          ctx.fillText(n.label, n.x + n.radius + 6, n.y + 3)
        }
      }

      animId = requestAnimationFrame(render)
    }

    render()

    return () => {
      cancelAnimationFrame(animId)
      window.removeEventListener('resize', handleResize)
      window.removeEventListener('mousemove', handleMouseMove)
      document.removeEventListener('mouseleave', handleMouseLeave)
    }
  }, [])

  return (
    <div className="absolute inset-0 pointer-events-none overflow-hidden z-0">
      <canvas
        ref={canvasRef}
        className="w-full h-full block opacity-75"
        style={{ mixBlendMode: 'screen' }}
      />
    </div>
  )
}
