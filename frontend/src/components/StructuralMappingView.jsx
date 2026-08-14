import React, { useEffect, useRef, useMemo, useState, useCallback } from 'react'
import { X, Network, RotateCw, ZoomIn, ZoomOut, Maximize2, Minimize2, Move, GripHorizontal } from 'lucide-react'

/**
 * StructuralMappingView — renders an interactive, force-directed graph of the scan's
 * attack surface: target → modules → severity clusters → sampled findings.
 * Supports Zoom (wheel/buttons), Pan (drag), Fullscreen, and Node Tooltips.
 *
 * Positions are computed ONCE via a deterministic force layout (seeded, no Math.random)
 * and stored in a ref so they survive re-renders. Dragging mutates the ref and triggers
 * a React state bump so links and nodes re-draw in their new positions.
 */

const MAX_INDIVIDUAL_FINDINGS = 150

const severityColor = {
  critical: '#DC2626',
  high: '#EA580C',
  medium: '#D97706',
  low: '#2563EB',
  info: '#64748B',
}

const severityOrder = ['critical', 'high', 'medium', 'low', 'info']

/* Simple seeded PRNG so layout is deterministic across renders */
function seededRandom(seed) {
  let s = seed
  return () => {
    s = (s * 16807 + 0) % 2147483647
    return (s - 1) / 2147483646
  }
}

export default function StructuralMappingView({ scan, findings, logs, onClose, onSelectFinding }) {
  const containerRef = useRef(null)

  // Zoom & Pan & Fullscreen state
  const [transform, setTransform] = useState({ scale: 1, x: 0, y: 0 })
  const [isPanning, setIsPanning] = useState(false)
  const panStartRef = useRef({ x: 0, y: 0 })
  const [hoveredNode, setHoveredNode] = useState(null)
  const [selectedCluster, setSelectedCluster] = useState(null)
  const [isFullscreen, setIsFullscreen] = useState(false)

  // Node drag state
  const [draggingNodeId, setDraggingNodeId] = useState(null)

  // Positions ref — survives re-renders, mutated by drag
  const posRef = useRef({})          // { [nodeId]: { x, y } }
  const layoutKeyRef = useRef('')    // fingerprint of last-laid-out topology
  const [tick, setTick] = useState(0) // bump to force re-render after drag

  // Build graph topology (nodes + links). Positions are NOT stored here.
  const { nodes, links, totalFindings, isGrouped, topoKey } = useMemo(() => {
    const _nodes = []
    const _links = []
    const allFindings = findings || []
    const grouped = allFindings.length > MAX_INDIVIDUAL_FINDINGS

    // Root node = target
    _nodes.push({ id: 'root', label: scan.target || 'Unknown Target', type: 'target' })

    // Extract subdomains from logs
    const subdomainSet = new Set()
    const endpointSet = new Set()
    ;(logs || []).forEach((l) => {
      const msg = l.message || ''
      const urlMatches = msg.match(/https?:\/\/[^\s,;]+/g) || []
      urlMatches.forEach((u) => {
        try {
          const parsed = new URL(u)
          endpointSet.add(parsed.origin + parsed.pathname)
          if (parsed.hostname !== scan.target) subdomainSet.add(parsed.hostname)
        } catch { /* ignore */ }
      })
    })

    // Add subdomain nodes (cap at 30)
    let si = 0
    subdomainSet.forEach((sub) => {
      if (si >= 30) return
      _nodes.push({ id: `sub-${si}`, label: sub, type: 'subdomain' })
      _links.push({ source: 'root', target: `sub-${si}` })
      si++
    })

    // Add endpoint nodes (cap at 30)
    let ei = 0
    endpointSet.forEach((ep) => {
      if (ei >= 30) return
      const nodeId = `ep-${ei}`
      _nodes.push({ id: nodeId, label: ep, type: 'endpoint' })
      _links.push({ source: subdomainSet.size > 0 ? 'sub-0' : 'root', target: nodeId })
      ei++
    })

    if (grouped) {
      // ——— GROUPED MODE ———
      const byModule = {}
      const findingsByModuleSev = {}

      allFindings.forEach((f) => {
        const sev = f.severity || 'info'
        const mod = f.module || 'code-auditor'
        if (!byModule[mod]) byModule[mod] = {}
        byModule[mod][sev] = (byModule[mod][sev] || 0) + 1

        const key = `${mod}-${sev}`
        if (!findingsByModuleSev[key]) findingsByModuleSev[key] = []
        findingsByModuleSev[key].push(f)
      })

      const moduleIds = {}
      Object.keys(byModule).forEach((mod, mi) => {
        const modTotal = Object.values(byModule[mod]).reduce((a, b) => a + b, 0)
        const modId = `mod-${mi}`
        moduleIds[mod] = modId
        _nodes.push({
          id: modId, label: mod, type: 'module', count: modTotal,
        })
        _links.push({ source: 'root', target: modId })
      })

      Object.keys(byModule).forEach((mod) => {
        Object.keys(byModule[mod]).forEach((sev) => {
          const cnt = byModule[mod][sev]
          const clusterId = `cluster-${mod}-${sev}`
          const key = `${mod}-${sev}`
          _nodes.push({
            id: clusterId, label: `${mod} / ${sev}`, type: 'cluster',
            module: mod, severity: sev, count: cnt,
            clusterFindings: findingsByModuleSev[key] || [],
          })
          _links.push({ source: moduleIds[mod], target: clusterId })
        })
      })

      // Sample findings (up to 4 per severity per module)
      const sampledPerKey = {}
      allFindings.forEach((f, idx) => {
        const sev = f.severity || 'info'
        const mod = f.module || 'code-auditor'
        const key = `${mod}-${sev}`
        if (!sampledPerKey[key]) sampledPerKey[key] = 0
        if (sampledPerKey[key] < 4) {
          const nodeId = `find-${idx}`
          _nodes.push({
            id: nodeId, label: f.title || 'Untitled', type: 'finding',
            module: mod, severity: sev, cwe: f.cwe_id, cvss: f.cvss,
            findingData: f,
          })
          _links.push({ source: `cluster-${mod}-${sev}`, target: nodeId })
          sampledPerKey[key]++
        }
      })
    } else {
      // ——— UNGROUPED MODE ———
      allFindings.forEach((f, idx) => {
        const nodeId = `find-${idx}`
        _nodes.push({
          id: nodeId, label: f.title || 'Untitled', type: 'finding',
          severity: f.severity, cwe: f.cwe_id, cvss: f.cvss,
          findingData: f,
        })
        _links.push({ source: 'root', target: nodeId })
      })
    }

    // Stable topology fingerprint — only changes when actual node set changes
    const topoKey = _nodes.map((n) => n.id).sort().join('|')
    return { nodes: _nodes, links: _links, totalFindings: allFindings.length, isGrouped: grouped, topoKey }
  }, [scan, findings, logs])

  // Run force layout ONLY when topology actually changes — store in posRef
  useEffect(() => {
    if (nodes.length === 0) return
    // Skip if we already laid out this exact topology
    if (layoutKeyRef.current === topoKey) return
    layoutKeyRef.current = topoKey

    const el = containerRef.current
    const width = el ? el.clientWidth : 1200
    const height = el ? el.clientHeight : 750
    const cx = width / 2, cy = height / 2

    const nodeCount = nodes.length
    const spacingFactor = Math.max(1, nodeCount / 40)

    const rng = seededRandom(42)

    // Group nodes by type for even 360-degree radial ring placement
    const nodesByType = {}
    nodes.forEach((n) => {
      if (!nodesByType[n.type]) nodesByType[n.type] = []
      nodesByType[n.type].push(n)
    })

    // Initialize positions in generous radial orbits
    const pos = {}
    const vel = {}
    nodes.forEach((n) => {
      if (n.type === 'target') {
        pos[n.id] = { x: cx, y: cy }
      } else {
        const typeGroup = nodesByType[n.type] || [n]
        const typeIndex = typeGroup.findIndex((item) => item.id === n.id)
        const angle = (typeIndex / Math.max(typeGroup.length, 1)) * Math.PI * 2 + (rng() - 0.5) * 0.2

        let radius = 400 * spacingFactor
        if (n.type === 'subdomain') radius = 260 * spacingFactor
        else if (n.type === 'endpoint') radius = 420 * spacingFactor
        else if (n.type === 'module') radius = 550 * spacingFactor
        else if (n.type === 'cluster') radius = 700 * spacingFactor
        else if (n.type === 'finding') radius = 850 * spacingFactor

        pos[n.id] = {
          x: cx + Math.cos(angle) * radius + (rng() - 0.5) * 80 * spacingFactor,
          y: cy + Math.sin(angle) * radius + (rng() - 0.5) * 80 * spacingFactor,
        }
      }
      vel[n.id] = { vx: 0, vy: 0 }
    })

    const nodeById = Object.fromEntries(nodes.map((n) => [n.id, n]))
    const N = nodes.length
    const ids = nodes.map((n) => n.id)

    // Run 140 physics ticks synchronously for smooth spreading
    for (let step = 0; step < 140; step++) {
      const damping = 0.85

      // Repulsion between ALL nodes (stronger force to avoid text overlap)
      for (let i = 0; i < N; i++) {
        for (let k = i + 1; k < N; k++) {
          const a = ids[i], b = ids[k]
          const dx = pos[a].x - pos[b].x
          const dy = pos[a].y - pos[b].y
          const distSq = dx * dx + dy * dy
          if (distSq > 1000000) continue
          const dist = Math.sqrt(distSq) || 0.1
          const force = Math.min(6000 / (distSq + 200), 10.0)
          const fx = (dx / dist) * force
          const fy = (dy / dist) * force
          vel[a].vx += fx; vel[a].vy += fy
          vel[b].vx -= fx; vel[b].vy -= fy
        }
      }

      // Link attraction (generous ideal distance)
      for (let li = 0; li < links.length; li++) {
        const l = links[li]
        const sp = pos[l.source], tp = pos[l.target]
        if (!sp || !tp) continue
        const sn = nodeById[l.target]
        const dx = sp.x - tp.x
        const dy = sp.y - tp.y
        const dist = Math.sqrt(dx * dx + dy * dy) || 1
        const idealDist = sn?.type === 'finding' ? 380 : sn?.type === 'cluster' ? 340 : 280
        const force = 0.015 * (dist - idealDist)
        const fx = (dx / dist) * force
        const fy = (dy / dist) * force
        vel[l.source].vx -= fx; vel[l.source].vy -= fy
        vel[l.target].vx += fx; vel[l.target].vy += fy
      }

      // Gentle center gravity
      ids.forEach((id) => {
        vel[id].vx += (cx - pos[id].x) * 0.0002
        vel[id].vy += (cy - pos[id].y) * 0.0002
      })

      // Update positions
      ids.forEach((id) => {
        vel[id].vx *= damping; vel[id].vy *= damping
        pos[id].x += vel[id].vx; pos[id].y += vel[id].vy
      })
    }

    // Auto-fit zoom
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity
    ids.forEach((id) => {
      if (pos[id].x < minX) minX = pos[id].x
      if (pos[id].x > maxX) maxX = pos[id].x
      if (pos[id].y < minY) minY = pos[id].y
      if (pos[id].y > maxY) maxY = pos[id].y
    })

    const graphWidth = (maxX - minX) || 500
    const graphHeight = (maxY - minY) || 500
    const graphCx = (minX + maxX) / 2
    const graphCy = (minY + maxY) / 2

    const fitScaleX = (width - 120) / graphWidth
    const fitScaleY = (height - 120) / graphHeight
    const autoScale = Math.min(Math.max(Math.min(fitScaleX, fitScaleY), 0.15), 2.2)
    const effectiveScale = nodeCount > 80 ? Math.min(autoScale, 0.35) : autoScale

    const autoX = width / 2 - graphCx * effectiveScale
    const autoY = height / 2 - graphCy * effectiveScale

    // Commit to refs
    posRef.current = pos
    setTransform({ scale: effectiveScale, x: autoX, y: autoY })
    setTick((t) => t + 1) // force re-render with final positions
  }, [nodes, links, topoKey])

  // Helper: get position for a node id
  const getPos = useCallback((id) => posRef.current[id] || { x: 0, y: 0 }, [])

  // Mouse wheel zoom
  const handleWheel = useCallback((e) => {
    e.preventDefault()
    const zoomFactor = e.deltaY < 0 ? 1.15 : 0.85
    setTransform((prev) => {
      const newScale = Math.min(Math.max(prev.scale * zoomFactor, 0.08), 5)
      return { ...prev, scale: newScale }
    })
  }, [])

  // Pan handlers
  const handleMouseDown = useCallback((e) => {
    if (e.target.closest('.graph-node')) return
    setIsPanning(true)
    panStartRef.current = { x: e.clientX - transform.x, y: e.clientY - transform.y }
  }, [transform.x, transform.y])

  const handleMouseMove = useCallback((e) => {
    if (draggingNodeId) {
      // Node drag — update posRef and bump tick
      const el = containerRef.current
      if (!el) return
      const rect = el.getBoundingClientRect()
      const svgX = (e.clientX - rect.left - transform.x) / transform.scale
      const svgY = (e.clientY - rect.top - transform.y) / transform.scale
      posRef.current[draggingNodeId] = { x: svgX, y: svgY }
      setTick((t) => t + 1)
      return
    }

    if (!isPanning) return
    setTransform((prev) => ({
      ...prev,
      x: e.clientX - panStartRef.current.x,
      y: e.clientY - panStartRef.current.y,
    }))
  }, [draggingNodeId, isPanning, transform.x, transform.y, transform.scale])

  const handleMouseUp = useCallback(() => {
    setIsPanning(false)
    setDraggingNodeId(null)
  }, [])

  // Node drag start
  const handleNodeMouseDown = useCallback((e, n) => {
    e.stopPropagation()
    e.preventDefault()
    setDraggingNodeId(n.id)
  }, [])

  // Zoom controls
  const zoomIn = () => setTransform((p) => ({ ...p, scale: Math.min(p.scale * 1.25, 5) }))
  const zoomOut = () => setTransform((p) => ({ ...p, scale: Math.max(p.scale / 1.25, 0.08) }))
  const resetView = () => {
    layoutKeyRef.current = ''
    posRef.current = {}
    setTick((t) => t + 1)
  }

  const getNodeColor = (n) => {
    if (n.type === 'target') return '#0EA5E9'
    if (n.type === 'subdomain') return '#A78BFA'
    if (n.type === 'endpoint') return '#F59E0B'
    if (n.type === 'module') return '#06B6D4'
    if (n.type === 'cluster') return severityColor[n.severity] || '#64748B'
    if (n.type === 'finding') return severityColor[n.severity] || '#EF4444'
    return '#64748B'
  }

  const getNodeRadius = (n) => {
    if (n.type === 'target') return 34
    if (n.type === 'module') return 24
    if (n.type === 'cluster') return Math.min(16 + Math.sqrt(n.count || 1) * 2.2, 38)
    if (n.type === 'subdomain') return 16
    if (n.type === 'endpoint') return 14
    return 11
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-md p-2 sm:p-4">
      <div
        className={`w-full transition-all duration-300 card flex flex-col overflow-hidden bg-ink-950 border border-slate-700/60 shadow-2xl ${
          isFullscreen ? 'fixed inset-0 z-50 rounded-none w-screen h-screen' : 'max-w-[96vw] h-[92vh] rounded-2xl'
        }`}
      >
        {/* Top Bar Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-white/10 bg-ink-900/80">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-accent/10 border border-accent/30 text-accent">
              <Network size={22} />
            </div>
            <div>
              <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                Structural Attack Surface Map
                <span className="text-xs font-normal px-2.5 py-0.5 rounded-full bg-accent/15 text-accent border border-accent/30">
                  {totalFindings} findings
                </span>
              </h2>
              <p className="text-xs text-slate-400">
                {nodes.length} nodes • {links.length} relationships
                {isGrouped ? ' (Severity Cluster View)' : ' (Full Node View)'}
              </p>
            </div>
          </div>

          {/* Interactive Control Buttons */}
          <div className="flex items-center gap-2">
            <div className="flex items-center bg-ink-800/80 rounded-xl p-1 border border-slate-700/60 mr-2">
              <button
                onClick={zoomIn}
                className="p-2 rounded-lg text-slate-300 hover:text-white hover:bg-white/10 transition-colors"
                title="Zoom In (+)"
              >
                <ZoomIn size={18} />
              </button>
              <span className="text-xs text-slate-400 font-mono px-2 min-w-[45px] text-center">
                {Math.round(transform.scale * 100)}%
              </span>
              <button
                onClick={zoomOut}
                className="p-2 rounded-lg text-slate-300 hover:text-white hover:bg-white/10 transition-colors"
                title="Zoom Out (-)"
              >
                <ZoomOut size={18} />
              </button>
              <button
                onClick={resetView}
                className="p-2 rounded-lg text-slate-300 hover:text-white hover:bg-white/10 transition-colors border-l border-slate-700/60 ml-1"
                title="Reset View & Simulation"
              >
                <RotateCw size={18} />
              </button>
            </div>

            <button
              onClick={() => setIsFullscreen(!isFullscreen)}
              className="p-2 rounded-xl text-slate-300 hover:text-white bg-ink-800/80 hover:bg-white/10 border border-slate-700/60 transition-colors"
              title={isFullscreen ? 'Exit Fullscreen' : 'Fullscreen'}
            >
              {isFullscreen ? <Minimize2 size={18} /> : <Maximize2 size={18} />}
            </button>

            <button
              onClick={onClose}
              className="p-2 rounded-xl text-slate-400 hover:text-white bg-ink-800/80 hover:bg-red-500/20 hover:border-red-500/40 border border-slate-700/60 transition-colors ml-2"
            >
              <X size={20} />
            </button>
          </div>
        </div>

        {/* SVG Canvas Area */}
        <div
          ref={containerRef}
          className={`flex-1 relative overflow-hidden bg-ink-950 ${isPanning ? 'cursor-grabbing' : 'cursor-grab'}`}
          onWheel={handleWheel}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
        >
          <svg className="w-full h-full">
            <g transform={`translate(${transform.x}, ${transform.y}) scale(${transform.scale})`}>
              {/* Links — rendered from posRef positions */}
              <g stroke="#334155" strokeWidth="1.5" opacity="0.45">
                {links.map((l, i) => {
                  const sp = getPos(l.source)
                  const tp = getPos(l.target)
                  return (
                    <line
                      key={i}
                      className="graph-link"
                      x1={sp.x}
                      y1={sp.y}
                      x2={tp.x}
                      y2={tp.y}
                    />
                  )
                })}
              </g>

              {/* Nodes — rendered from posRef positions */}
              <g>
                {nodes.map((n) => {
                  const p = getPos(n.id)
                  const isHovered = hoveredNode?.id === n.id
                  const radius = getNodeRadius(n)
                  return (
                    <g
                      key={n.id}
                      className={`graph-node ${n.type === 'finding' || n.type === 'cluster' ? 'cursor-pointer' : 'cursor-grab'}`}
                      data-node-id={n.id}
                      transform={`translate(${p.x},${p.y})`}
                      onMouseEnter={() => setHoveredNode(n)}
                      onMouseLeave={() => setHoveredNode(null)}
                      onMouseDown={(e) => handleNodeMouseDown(e, n)}
                      onClick={() => {
                        if (n.type === 'finding' && n.findingData && onSelectFinding) {
                          onSelectFinding(n.findingData)
                        } else if (n.type === 'cluster') {
                          setSelectedCluster(n)
                        } else if (n.type === 'target') {
                          setTransform((prev) => ({
                            ...prev,
                            scale: Math.min(prev.scale * 1.8, 4),
                            x: 0, y: 0,
                          }))
                        } else if (n.type === 'subdomain' || n.type === 'endpoint') {
                          setHoveredNode(n)
                        }
                      }}
                    >
                      {/* Pulse glow background ring for hovered or target node */}
                      {(isHovered || n.type === 'target') && (
                        <circle
                          r={radius + 8}
                          fill="none"
                          stroke={getNodeColor(n)}
                          strokeWidth="2"
                          opacity="0.5"
                          className="animate-pulse"
                        />
                      )}

                      <circle
                        r={radius}
                        fill={getNodeColor(n)}
                        stroke={isHovered ? '#FFFFFF' : '#0F172A'}
                        strokeWidth={isHovered ? '3' : '2'}
                      />

                      {/* Count for clusters */}
                      {n.type === 'cluster' && (
                        <text
                          textAnchor="middle"
                          dy="5"
                          fontSize="12"
                          fontWeight="bold"
                          fill="#FFFFFF"
                          pointerEvents="none"
                        >
                          {n.count}
                        </text>
                      )}

                      {/* Node Label Text */}
                      {n.type !== 'cluster' && (
                        <text
                          textAnchor="middle"
                          dy={radius + 14}
                          fontSize="10"
                          fontWeight="500"
                          fill="#CBD5E1"
                          pointerEvents="none"
                        >
                          {n.label?.substring(0, 18)}
                        </text>
                      )}
                      {n.type === 'cluster' && (
                        <text
                          textAnchor="middle"
                          dy={radius + 14}
                          fontSize="10"
                          fontWeight="600"
                          fill="#94A3B8"
                          pointerEvents="none"
                        >
                          {n.module} ({n.severity})
                        </text>
                      )}
                    </g>
                  )
                })}
              </g>
            </g>
          </svg>

          {/* Cluster Findings Slide-Over Drawer */}
          {selectedCluster && (
            <div className="absolute top-0 right-0 bottom-0 w-96 bg-ink-900/98 border-l border-slate-700/80 backdrop-blur-xl p-5 overflow-y-auto z-30 shadow-2xl space-y-4">
              <div className="flex items-center justify-between border-b border-white/10 pb-3">
                <div>
                  <span
                    className="px-2 py-0.5 text-[10px] font-bold uppercase rounded-md text-white mr-2"
                    style={{ backgroundColor: severityColor[selectedCluster.severity] }}
                  >
                    {selectedCluster.severity}
                  </span>
                  <h3 className="text-sm font-bold text-slate-100 inline">
                    {selectedCluster.module} Cluster
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    {selectedCluster.clusterFindings?.length || 0} findings in this cluster. Click any to open details.
                  </p>
                </div>
                <button
                  onClick={() => setSelectedCluster(null)}
                  className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-white/10"
                >
                  <X size={18} />
                </button>
              </div>

              <div className="space-y-2.5">
                {selectedCluster.clusterFindings?.map((f, idx) => (
                  <div
                    key={f.id || idx}
                    onClick={() => {
                      if (onSelectFinding) onSelectFinding(f)
                    }}
                    className="p-3 rounded-xl bg-ink-800/80 hover:bg-accent/10 border border-slate-700/60 hover:border-accent/40 transition-all cursor-pointer group"
                  >
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <span className="text-[11px] font-mono text-cyan-400 truncate">
                        {f.cwe_id || f.module}
                      </span>
                      {f.cvss && (
                        <span className="text-[10px] font-bold px-1.5 py-0.5 bg-red-500/20 text-red-300 rounded border border-red-500/30">
                          CVSS {f.cvss}
                        </span>
                      )}
                    </div>
                    <h4 className="text-xs font-semibold text-slate-200 group-hover:text-white line-clamp-2">
                      {f.title}
                    </h4>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Floating Hover Tooltip */}
          {hoveredNode && !selectedCluster && (
            <div className="absolute top-6 left-6 z-20 bg-ink-900/95 border border-cyan-500/40 backdrop-blur-md rounded-2xl p-4 shadow-2xl max-w-sm pointer-events-none space-y-2">
              <div className="flex items-center justify-between gap-2 border-b border-white/10 pb-2">
                <span className="text-xs uppercase font-semibold text-cyan-400 tracking-wider">
                  {hoveredNode.type} Node
                </span>
                {hoveredNode.severity && (
                  <span
                    className="px-2 py-0.5 text-[10px] font-bold uppercase rounded-md text-white"
                    style={{ backgroundColor: severityColor[hoveredNode.severity] }}
                  >
                    {hoveredNode.severity}
                  </span>
                )}
              </div>
              <p className="text-sm font-bold text-slate-100 break-words">{hoveredNode.label}</p>
              {hoveredNode.count && (
                <p className="text-xs text-slate-300">
                  Contains <strong className="text-accent">{hoveredNode.count}</strong> findings in module{' '}
                  <code className="text-cyan-300 font-mono">{hoveredNode.module}</code>. Click to expand list!
                </p>
              )}
              {hoveredNode.type === 'finding' && (
                <p className="text-xs text-cyan-400 font-medium">✨ Click node to open finding details drawer!</p>
              )}
            </div>
          )}

          {/* Bottom Left Legend */}
          <div className="absolute bottom-6 left-6 bg-ink-900/90 backdrop-blur-md rounded-2xl p-4 border border-slate-800 space-y-2 shadow-xl">
            <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2 flex items-center justify-between gap-4">
              <span>Legend</span>
              <span className="text-[10px] font-normal text-slate-500 flex items-center gap-1">
                <GripHorizontal size={12} /> Drag Nodes • <Move size={12} /> Pan • Wheel Zoom
              </span>
            </div>
            <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
              <div className="flex items-center gap-2">
                <div className="w-3.5 h-3.5 rounded-full bg-[#0EA5E9]" />
                <span className="text-slate-300">Target</span>
              </div>
              {isGrouped && (
                <div className="flex items-center gap-2">
                  <div className="w-3.5 h-3.5 rounded-full bg-[#06B6D4]" />
                  <span className="text-slate-300">Module</span>
                </div>
              )}
              <div className="flex items-center gap-2">
                <div className="w-3.5 h-3.5 rounded-full bg-[#A78BFA]" />
                <span className="text-slate-300">Subdomain</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3.5 h-3.5 rounded-full bg-[#F59E0B]" />
                <span className="text-slate-300">Endpoint</span>
              </div>
              {severityOrder.map((sev) => (
                <div key={sev} className="flex items-center gap-2">
                  <div className="w-3.5 h-3.5 rounded-full" style={{ backgroundColor: severityColor[sev] }} />
                  <span className="text-slate-300 capitalize">{sev}{isGrouped ? ' Cluster' : ''}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
