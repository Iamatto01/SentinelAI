export class AICostTracker {
  constructor() {
    this.projectTotals = new Map()
    this.sessionTotals = new Map()
    this.projectBudgets = new Map()

    this.inputRatePer1M = Number(process.env.AI_COST_INPUT_PER_1M || 0.05)
    this.outputRatePer1M = Number(process.env.AI_COST_OUTPUT_PER_1M || 0.08)

    this.loadBudgetsFromEnv()
  }

  loadBudgetsFromEnv() {
    const json = process.env.AI_PROJECT_BUDGETS_JSON || '{}'
    try {
      const parsed = JSON.parse(json)
      for (const [projectId, amount] of Object.entries(parsed)) {
        const value = Number(amount)
        if (!Number.isNaN(value) && value >= 0) {
          this.projectBudgets.set(projectId, value)
        }
      }
    } catch (_) {
      // Ignore malformed budget config.
    }
  }

  setProjectBudget(projectId, budgetUsd) {
    const val = Number(budgetUsd)
    if (Number.isNaN(val) || val < 0) return false
    this.projectBudgets.set(projectId, val)
    return true
  }

  getProjectBudget(projectId) {
    if (!projectId) return null
    return this.projectBudgets.get(projectId) ?? null
  }

  estimateCost({ promptTokens = 0, completionTokens = 0 }) {
    const inputCost = (Number(promptTokens) / 1_000_000) * this.inputRatePer1M
    const outputCost = (Number(completionTokens) / 1_000_000) * this.outputRatePer1M
    return Number((inputCost + outputCost).toFixed(8))
  }

  trackUsage({ projectId = null, sessionId = null, operation = 'unknown', model = 'unknown', usage = {} }) {
    const promptTokens = Number(usage.prompt_tokens || usage.input_tokens || 0)
    const completionTokens = Number(usage.completion_tokens || usage.output_tokens || 0)
    const totalTokens = Number(usage.total_tokens || promptTokens + completionTokens)
    const costUsd = this.estimateCost({ promptTokens, completionTokens })

    const event = {
      timestamp: new Date().toISOString(),
      projectId,
      sessionId,
      operation,
      model,
      usage: { promptTokens, completionTokens, totalTokens },
      costUsd,
    }

    if (projectId) {
      const current = this.projectTotals.get(projectId) || {
        totalCostUsd: 0,
        totalPromptTokens: 0,
        totalCompletionTokens: 0,
        totalTokens: 0,
        events: [],
      }
      current.totalCostUsd = Number((current.totalCostUsd + costUsd).toFixed(8))
      current.totalPromptTokens += promptTokens
      current.totalCompletionTokens += completionTokens
      current.totalTokens += totalTokens
      current.events.push(event)
      this.projectTotals.set(projectId, current)
    }

    if (sessionId) {
      const current = this.sessionTotals.get(sessionId) || {
        totalCostUsd: 0,
        totalPromptTokens: 0,
        totalCompletionTokens: 0,
        totalTokens: 0,
        events: [],
      }
      current.totalCostUsd = Number((current.totalCostUsd + costUsd).toFixed(8))
      current.totalPromptTokens += promptTokens
      current.totalCompletionTokens += completionTokens
      current.totalTokens += totalTokens
      current.events.push(event)
      this.sessionTotals.set(sessionId, current)
    }

    return event
  }

  getProjectSummary(projectId) {
    const totals = this.projectTotals.get(projectId) || {
      totalCostUsd: 0,
      totalPromptTokens: 0,
      totalCompletionTokens: 0,
      totalTokens: 0,
      events: [],
    }
    const budgetUsd = this.getProjectBudget(projectId)
    const remainingUsd = budgetUsd == null ? null : Number((budgetUsd - totals.totalCostUsd).toFixed(8))

    return {
      projectId,
      ...totals,
      budgetUsd,
      remainingUsd,
      budgetExceeded: budgetUsd == null ? false : totals.totalCostUsd > budgetUsd,
    }
  }

  canSpend(projectId, expectedExtraUsd = 0) {
    const budget = this.getProjectBudget(projectId)
    if (budget == null) return { allowed: true }
    const summary = this.getProjectSummary(projectId)
    const afterSpend = summary.totalCostUsd + Number(expectedExtraUsd || 0)
    if (afterSpend > budget) {
      return {
        allowed: false,
        reason: `AI budget exceeded for project ${projectId} (${afterSpend.toFixed(6)} > ${budget.toFixed(6)} USD)`,
        summary,
      }
    }
    return { allowed: true, summary }
  }

  getAllProjectSummaries() {
    const ids = new Set([...this.projectTotals.keys(), ...this.projectBudgets.keys()])
    return [...ids].map((id) => this.getProjectSummary(id))
  }

  getSessionSummary(sessionId) {
    return this.sessionTotals.get(sessionId) || {
      totalCostUsd: 0,
      totalPromptTokens: 0,
      totalCompletionTokens: 0,
      totalTokens: 0,
      events: [],
    }
  }
}
