import fs from 'node:fs'
import path from 'node:path'
import { config } from '../config.js'

/**
 * Agent Registry — loads all 53 pentest-ai-agents specialist personas and
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
    // Only the finding's own identity drives routing — never the arbitrary text
    // of an evidence blob, which routinely contains words like "injection" or
    // "token" and would misfile a missing-header finding to the SQL specialist.
    const claims = `${finding.title || ''} ${finding.description || ''} ${finding.cweId || ''}`.toLowerCase()
    const mod = String(finding.module || '').toLowerCase()
    const rules = [
      // Ordered most-specific first: a description that merely mentions the word
      // "endpoint" or "port" in passing must not outrank a rule that names the
      // actual class of weakness (header posture, version fingerprint, SQLi).
      [/missing.*(?:header|hsts|csp|content-security|x-frame|referrer|permissions|transport)|security header|\bcors\b|access-control|cookie|clickjack/, 'web-hunter'],
      [/fingerprint|banner grab|technology stack|architecture|product version|outdated|component lifecycle|\bcve-\d/, 'vuln-scanner'],
      [/\bsql\b|sqli|sql injection|nosql/, 'database-attacker'],
      [/xss|cross-site scripting|\bdom-based/, 'web-hunter'],
      [/ssrf|request forgery/, 'web-hunter'],
      [/graphql|\brest api\b|\bapi endpoint|openapi|swagger|mass assignment|bola|bfla/, 'api-security'],
      [/secret|\bapi key|hardcoded|private key|leaked credential/, 'code-auditor'],
      [/deserializ|prototype pollution|\bsast\b|static analysis|source code/, 'code-auditor'],
      [/business logic|workflow bypass|price manipulation|race condition/, 'bizlogic-hunter'],
      [/cloud|aws|azure|gcp|s3 bucket|\biam\b|metadata service/, 'cloud-security'],
      [/container|docker|kubernetes|\bk8s\b/, 'container-breakout'],
      [/crypto|cipher|certificate|\btls\b|\bssl\b|hashing algorithm/, 'crypto-analyzer'],
      [/authentication|\bjwt\b|session fixation|login|password|oauth|\bsso\b/, 'credential-tester'],
      [/network|open port|\bsmb\b|\bldap\b|kerberos|active directory|\bnmap\b/, 'network-attacker'],
      [/mobile client|android|\bios\b|\bapk\b/, 'mobile-pentester'],
      [/iot|firmware|embedded device/, 'iot-pentester'],
      [/\bllm\b|prompt injection|jailbreak|ai model/, 'llm-redteam'],
      [/misconfiguration|hardening/, 'web-hunter'],
    ]
    for (const [re, agent] of rules) if (re.test(claims)) return agent
    // Second pass: the module the finding came from is still a weak but valid
    // routing signal.
    if (/version|lifecycle|whatweb|technology/.test(mod)) return 'vuln-scanner'
    if (/nmap|masscan|portscan|network/.test(mod)) return 'network-attacker'
    if (/secret|code-audit|sast/.test(mod)) return 'code-auditor'
    if (/cloud|s3|iam/.test(mod)) return 'cloud-security'
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
