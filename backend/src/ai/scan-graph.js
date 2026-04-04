const AI_SCAN_GRAPH = [
  { id: 'optimize', title: 'Optimize Strategy', deps: [] },
  { id: 'scan', title: 'Run Scan', deps: ['optimize'] },
  { id: 'analyze', title: 'Enhance Vulnerabilities', deps: ['scan'] },
  { id: 'followup', title: 'Plan Follow-Up', deps: ['analyze'] },
]

export function buildAIScanGraph() {
  return AI_SCAN_GRAPH.map((s) => ({ ...s }))
}

export async function executeAIScanGraph({ graph, handlers, onStep }) {
  const completed = new Set()
  const outputs = {}

  while (completed.size < graph.length) {
    const next = graph.find((step) => !completed.has(step.id) && step.deps.every((d) => completed.has(d)))
    if (!next) {
      throw new Error('Graph execution blocked by cyclic or unresolved dependencies')
    }

    if (onStep) await onStep('started', next)
    const startedAt = Date.now()
    outputs[next.id] = await handlers[next.id]()
    const durationMs = Date.now() - startedAt
    if (onStep) await onStep('completed', { ...next, durationMs, output: outputs[next.id] })
    completed.add(next.id)
  }

  return outputs
}
