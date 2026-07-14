import { dbGetIngestedLogs, dbUpdateIngestedLogsAnalysis } from '../database.js'

export class LogAnalyzer {
  constructor(options = {}) {
    this.aiWorker = options.aiWorker
    this.intervalMs = options.intervalMs || 60000 // Run every 60 seconds
    this.timer = null
    this.isRunning = false
  }

  start() {
    if (this.timer) return
    this.timer = setInterval(() => this.runAnalysisCycle(), this.intervalMs)
    // Run an initial cycle after 5 seconds
    setTimeout(() => this.runAnalysisCycle(), 5000)
  }

  stop() {
    if (this.timer) {
      clearInterval(this.timer)
      this.timer = null
    }
  }

  async runAnalysisCycle() {
    if (this.isRunning) return
    this.isRunning = true

    try {
      // Fetch unanalyzed logs
      const unanalyzedLogs = await dbGetIngestedLogs({ analyzed: false, limit: 50 })
      if (unanalyzedLogs.length === 0) {
        this.isRunning = false
        return
      }

      console.log(`[Log Analyzer] Processing ${unanalyzedLogs.length} unanalyzed logs...`)

      // Group logs by source and level to analyze together
      const groups = {}
      for (const log of unanalyzedLogs) {
        const key = `${log.source}_${log.level}`
        if (!groups[key]) groups[key] = []
        groups[key].push(log)
      }

      const updates = []

      for (const [key, logs] of Object.entries(groups)) {
        // If it's a bunch of INFO logs, we might just mark them analyzed to save AI tokens,
        // but for now let's analyze WARNING and ERROR logs deeply, and do a quick pass on INFO.
        const level = logs[0].level
        if (level === 'info' && logs.length < 5) {
          // Skip deep analysis for scattered info logs
          for (const l of logs) {
            updates.push({ id: l.id, aiAnalysis: 'Standard informational log.', anomalyScore: 0 })
          }
          continue
        }

        // Prepare prompt
        const logLines = logs.map(l => `[${l.timestamp}] ${l.message}`).join('\n')
        
        const prompt = `
You are a SIEM Log Analyzer expert. Analyze the following batch of logs from source "${logs[0].source}" with level "${level}".
Identify if there are any security anomalies, errors, brute-force attempts, or system crashes.
Return your response ONLY in the following JSON format:
{
  "analysis": "Brief 1-2 sentence summary of what these logs indicate.",
  "anomalyScore": <number between 0.0 and 1.0, where 1.0 is a critical threat/crash>
}

Logs to analyze:
${logLines}
`
        let aiResult = { analysis: 'Could not analyze', anomalyScore: 0 }
        
        if (this.aiWorker && this.aiWorker.isInitialized) {
          try {
            const reply = await this.aiWorker.generateResponse(prompt)
            // Extract JSON from markdown
            const jsonMatch = reply.match(/```json\n([\s\S]*?)\n```/) || reply.match(/\{[\s\S]*\}/)
            if (jsonMatch) {
              const jsonStr = jsonMatch[1] || jsonMatch[0]
              aiResult = JSON.parse(jsonStr)
            }
          } catch (aiErr) {
            console.error('[Log Analyzer] AI generation failed:', aiErr)
          }
        }

        // Apply result to all logs in this batch
        for (const l of logs) {
          updates.push({ 
            id: l.id, 
            aiAnalysis: aiResult.analysis, 
            anomalyScore: aiResult.anomalyScore || 0 
          })
        }
      }

      // Update DB
      if (updates.length > 0) {
        await dbUpdateIngestedLogsAnalysis(updates)
        const anomalies = updates.filter(u => u.anomalyScore >= 0.7).length
        if (anomalies > 0) {
          console.log(`🚨 [Log Analyzer] Found ${anomalies} high-severity anomalies!`)
        }
      }

    } catch (err) {
      console.error('[Log Analyzer] Cycle error:', err)
    } finally {
      this.isRunning = false
    }
  }
}
