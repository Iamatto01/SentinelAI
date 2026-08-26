import fs from 'node:fs'
import path from 'node:path'
import { config } from '../config.js'

/**
 * Agent Registry — loads all 53 pentest-ai-agents specialist personas and
 * routes findings/tasks to the right specialist. This is the reasoning layer
 * that SentinelAI lacked (it only had ~5 hardcoded personas).
 */
export class AgentRegistry {
  constructor() {
    this.agents = new Map()
    this.load()
  }

  load() {
    const dir = config.agentsDir
    if (!fs.existsSync(dir)) {
      console.warn(`[agents] directory not found: ${dir}`)
      return
    }
    let count = 0
    for (const file of fs.readdirSync(dir)) {
      if (!file.endsWith('.md') || file.startsWith('_')) continue
      try {
        const raw = fs.readFileSync(path.join(dir, file), 'utf8')
        const m = raw.match(/^---\s*([\s\S]*?)\s*---\s*([\s\S]*)$/)
        const body = m ? m[2].trim() : raw
        const fm = m ? m[1] : ''
        const name = (fm.match(/^name:\s*(.+)$/m)?.[1] || path.basename(file, '.md')).trim()
        const description = (fm.match(/^description:\s*(.+)$/m)?.[1] || '').trim()
        if (!this.agents.has(name)) {
          this.agents.set(name, { name, description, systemPrompt: body, file })
          count++
        }
      } catch { /* skip */ }
    }
    console.log(`[agents] loaded ${count} specialist personas from ${dir}`)
  }

  get(name) { return this.agents.get(name) || null }
  list() { return [...this.agents.values()].map(a => ({ name: a.name, description: a.description })) }
  prompt(name) { return this.get(name)?.systemPrompt || null }

  /**
   * Route a vulnerability/finding to the most appropriate specialist agent.
   * Keyword-based deterministic routing (fast, no LLM needed).
   */
  routeFinding(finding = {}) {
    const text = `${finding.title || ''} ${finding.description || ''} ${finding.cweId || ''} ${finding.module || ''}`.toLowerCase()
    const rules = [
      [/sql|sqli|injection/, 'database-attacker'],
      [/xss|cross-site scripting|dom/, 'web-hunter'],
      [/ssrf|request forgery/, 'web-hunter'],
      [/api|graphql|rest|endpoint/, 'api-security'],
      [/secret|credential|api key|token|hardcoded/, 'code-auditor'],
      [/code|sast|static|source|deserializ|logic/, 'code-auditor'],
      [/business logic|workflow|price|race/, 'bizlogic-hunter'],
      [/cloud|aws|azure|gcp|s3|iam/, 'cloud-security'],
      [/container|docker|kubernetes|k8s/, 'container-breakout'],
      [/crypto|tls|ssl|cipher|certificate|hash/, 'crypto-analyzer'],
      [/auth|jwt|session|login|password|oauth/, 'credential-tester'],
      [/network|port|smb|ldap|kerberos|active directory/, 'network-attacker'],
      [/mobile|android|ios|apk/, 'mobile-pentester'],
      [/iot|firmware|embedded/, 'iot-pentester'],
      [/llm|prompt|ai |model/, 'llm-redteam'],
      [/misconfig|header|cors|cookie/, 'web-hunter'],
      [/cve|outdated|component|dependenc/, 'vuln-scanner'],
    ]
    for (const [re, agent] of rules) if (re.test(text)) return agent
    return 'web-hunter' // default specialist
  }

  /** Route a whitebox/static-analysis task. */
  routeStatic(language = '', focus = '') {
    const t = `${language} ${focus}`.toLowerCase()
    if (/secret|credent|token/.test(t)) return 'code-auditor'
    if (/logic|business/.test(t)) return 'bizlogic-hunter'
    if (/api|graphql/.test(t)) return 'api-security'
    return 'code-auditor'
  }
}

export const agentRegistry = new AgentRegistry()
export default agentRegistry
