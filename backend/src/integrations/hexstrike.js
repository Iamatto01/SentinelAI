import { config } from '../config.js'

/**
 * Hexstrike Engine client.
 *
 * ARCHITECTURE UPGRADE over SentinelAI: instead of ~20 hand-rolled child_process
 * wrappers, ALL tool execution is delegated to the hexstrike_server.py REST API,
 * which provides 100+ tools with an IntelligentDecisionEngine, ParameterOptimizer,
 * process pooling, caching and intelligent error recovery.
 *
 * The backend stays a thin orchestration plane; hexstrike does the heavy lifting.
 */

const { url: BASE, enabled, timeoutMs } = config.hexstrike

async function http(path, body, { timeout = timeoutMs } = {}) {
  const ctrl = new AbortController()
  const t = setTimeout(() => ctrl.abort(), timeout)
  try {
    const res = await fetch(`${BASE}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {}),
      signal: ctrl.signal,
    })
    const text = await res.text()
    let json
    try { json = JSON.parse(text) } catch { json = { raw: text } }
    if (!res.ok) {
      return { success: false, error: json.error || `HTTP ${res.status}`, status: res.status, ...json }
    }
    return json
  } catch (e) {
    return { success: false, error: e.name === 'AbortError' ? `timeout after ${timeout}ms` : e.message, unavailable: true }
  } finally {
    clearTimeout(t)
  }
}

let cachedHealth = null
let healthAt = 0

/** Probe the hexstrike server, cache result for 30s. */
export async function engineStatus(force = false) {
  if (!enabled) return { enabled: false, available: false, reason: 'disabled-by-config' }
  if (!force && cachedHealth && Date.now() - healthAt < 30000) return cachedHealth
  try {
    const ctrl = new AbortController()
    const t = setTimeout(() => ctrl.abort(), 15000)
    const res = await fetch(`${BASE}/health`, { signal: ctrl.signal })
    clearTimeout(t)
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const j = await res.json()
    const totalToolsAvailable = Number(j.total_tools_available || 0)
    const totalTools = Number(j.total_tools_count || 0)
    cachedHealth = {
      ok: true,
      enabled: true,
      // A reachable API with no installed binaries cannot execute a scan.
      available: totalToolsAvailable > 0,
      operational: true,
      version: j.version,
      totalToolsAvailable,
      totalTools,
      categoryStats: j.category_stats,
      allEssential: j.all_essential_tools_available,
      error: totalToolsAvailable > 0 ? null : `no security tools available (0/${totalTools})`,
    }
  } catch (e) {
    cachedHealth = { enabled: true, available: false, error: e.message, url: BASE }
  }
  healthAt = Date.now()
  return cachedHealth
}

/** Run a single named tool via its dedicated hexstrike endpoint. */
export async function runTool(tool, params, opts) {
  if (!enabled) return { success: false, error: 'hexstrike-disabled' }
  return http(`/api/tools/${tool}`, params, opts)
}

/** AI-driven smart scan: hexstrike analyzes the target, picks tools, optimizes params, runs in parallel. */
export async function smartScan(target, { objective = 'comprehensive', maxTools = 6 } = {}) {
  if (!enabled) return { success: false, error: 'hexstrike-disabled' }
  return http(`/api/intelligence/smart-scan`, { target, objective, max_tools: maxTools })
}

/** Build an intelligent attack chain for a target without executing. */
export async function attackChain(target, objective = 'comprehensive') {
  if (!enabled) return { success: false, error: 'hexstrike-disabled' }
  return http(`/api/intelligence/create-attack-chain`, { target, objective })
}

/** Analyze a target (type detection, tech stack, profile). */
export async function analyzeTarget(target) {
  if (!enabled) return { success: false, error: 'hexstrike-disabled' }
  return http(`/api/intelligence/analyze-target`, { target })
}

/** Let hexstrike select optimal tools for a target/objective. */
export async function selectTools(target, objective = 'comprehensive') {
  if (!enabled) return { success: false, error: 'hexstrike-disabled' }
  return http(`/api/intelligence/select-tools`, { target, objective })
}

/** Generic command passthrough (escape hatch). */
export async function runCommand(command, useCache = true) {
  if (!enabled) return { success: false, error: 'hexstrike-disabled' }
  return http(`/api/command`, { command, use_cache: useCache })
}

/**
 * Target normalizers — tools have different input expectations:
 *  - URL tools (httpx/katana/sqlmap/dalfox/wpscan/arjun/dir fuzzers) NEED a scheme,
 *    otherwise they exit instantly with "no output".
 *  - Host tools (nmap/nikto/subfinder/amass/wafw00f) expect a bare host/domain.
 */
const toUrl = (t) => /^https?:\/\//i.test(t) ? t : `https://${t}`
const toHost = (t) => {
  try { return new URL(toUrl(t)).hostname } catch { return t.replace(/^https?:\/\//i, '').split('/')[0] }
}

/**
 * Map a logical scan module to a hexstrike tool call.
 * Returns a normalized finding-producing result.
 */
export const MODULE_TOOL_MAP = {
  nmap:        { tool: 'nmap',        params: (t) => ({ target: toHost(t), scan_type: '-sCV', additional_args: '-T4 -Pn' }) },
  rustscan:    { tool: 'rustscan',    params: (t) => ({ target: toHost(t) }) },
  masscan:     { tool: 'masscan',     params: (t) => ({ target: toHost(t) }) },
  gobuster:    { tool: 'gobuster',    params: (t) => ({ url: toUrl(t), mode: 'dir' }) },
  feroxbuster: { tool: 'feroxbuster', params: (t) => ({ url: toUrl(t) }) },
  dirsearch:   { tool: 'dirsearch',   params: (t) => ({ url: toUrl(t) }) },
  ffuf:        { tool: 'ffuf',        params: (t) => ({ url: toUrl(t) }) },
  nikto:       { tool: 'nikto',       params: (t) => ({ target: toHost(t) }) },
  nuclei:      { tool: 'nuclei',      params: (t) => ({ target: toUrl(t) }) },
  sqlmap:      { tool: 'sqlmap',      params: (t) => ({ url: toUrl(t) }) },
  dalfox:      { tool: 'dalfox',      params: (t) => ({ url: toUrl(t) }) },
  katana:      { tool: 'katana',      params: (t) => ({ url: toUrl(t) }) },
  httpx:       { tool: 'httpx',       params: (t) => ({ target: toUrl(t) }) },
  whatweb:     { tool: 'whatweb',     params: (t) => ({ target: toUrl(t) }), nativeOnly: true },
  wafw00f:     { tool: 'wafw00f',     params: (t) => ({ target: toUrl(t) }) },
  wpscan:      { tool: 'wpscan',      params: (t) => ({ url: toUrl(t) }) },
  arjun:       { tool: 'arjun',       params: (t) => ({ url: toUrl(t) }) },
  subfinder:   { tool: 'subfinder',   params: (t) => ({ domain: toHost(t) }) },
  amass:       { tool: 'amass',       params: (t) => ({ domain: toHost(t) }) },
  dnsbrute:    { tool: 'dnsbrute',    params: (t) => ({ domain: toHost(t) }), nativeOnly: true },
  zap:         { tool: 'zap',         params: (t) => ({ target: toUrl(t) }) },
  graphql:     { tool: 'graphql_scanner', params: (t) => ({ url: toUrl(t) }) },
  jwt:         { tool: 'jwt_analyzer',    params: (t) => ({ token: t }) },
}

export default { engineStatus, runTool, smartScan, attackChain, analyzeTarget, selectTools, runCommand, MODULE_TOOL_MAP }
