import fs from 'node:fs'
import path from 'node:path'
import { getDb } from '../db.js'
import { config } from '../config.js'

/**
 * PayloadsAllTheThings RAG engine.
 *
 * Unlike SentinelAI (which re-read & re-parsed markdown on every finding),
 * this builds a PERSISTENT FTS5 full-text index once, then retrieves ranked
 * PoC payloads in milliseconds. Supports category mapping + fuzzy search.
 */

const VULN_TYPE_MAP = {
  'sql injection': ['SQL Injection'], 'sqli': ['SQL Injection'],
  'xss': ['XSS Injection'], 'cross-site scripting': ['XSS Injection'],
  'command injection': ['Command Injection'], 'rce': ['Command Injection'],
  'ssti': ['Server Side Template Injection'], 'template injection': ['Server Side Template Injection'],
  'ssrf': ['Server Side Request Forgery'],
  'csrf': ['Cross-Site Request Forgery'],
  'lfi': ['File Inclusion'], 'rfi': ['File Inclusion'], 'file inclusion': ['File Inclusion'],
  'path traversal': ['Directory Traversal'], 'directory traversal': ['Directory Traversal'],
  'file upload': ['Upload Insecure Files'], 'upload': ['Upload Insecure Files'],
  'xxe': ['XXE Injection'], 'xml external entity': ['XXE Injection'],
  'idor': ['Insecure Direct Object References'],
  'jwt': ['JSON Web Token'], 'json web token': ['JSON Web Token'],
  'nosql': ['NoSQL Injection'],
  'ldap': ['LDAP Injection'], 'xpath': ['XPATH Injection'],
  'open redirect': ['Open Redirect'], 'redirect': ['Open Redirect'],
  'cors': ['CORS Misconfiguration'],
  'graphql': ['GraphQL Injection'],
  'deserialization': ['Insecure Deserialization'],
  'prototype pollution': ['Prototype Pollution'],
  'race condition': ['Race Condition'],
  'request smuggling': ['Request Smuggling'], 'smuggling': ['Request Smuggling'],
  'prompt injection': ['Prompt Injection'], 'llm': ['Prompt Injection'],
  'websocket': ['Web Sockets'],
  'oauth': ['OAuth Misconfiguration'],
  'saml': ['SAML Injection'],
  'crlf': ['CRLF Injection'],
  'type juggling': ['Type Juggling'],
  'business logic': ['Business Logic Errors'],
  'account takeover': ['Account Takeover'],
  'clickjacking': ['Clickjacking'],
  'zip slip': ['Zip Slip'],
  'api key': ['API Key Leaks'],
  'web cache': ['Web Cache Deception'],
}

let ftsReady = false

/** Build (or rebuild) the persistent FTS5 index from the markdown corpus. */
export function buildPayloadIndex(onLog = () => {}) {
  const dir = config.payloads.dir
  if (!fs.existsSync(dir)) {
    onLog('warn', `PayloadsAllTheThings corpus not found at ${dir}`)
    return { indexed: 0 }
  }
  const db = getDb()

  // FTS5 virtual table
  db.exec(`DROP TABLE IF EXISTS payload_fts;`)
  db.exec(`CREATE VIRTUAL TABLE payload_fts USING fts5(category, file, title, content, keywords);`)
  db.exec(`DELETE FROM payload_index;`)

  const insertMeta = db.prepare(`INSERT OR REPLACE INTO payload_index (category, file, title, content, keywords) VALUES (?,?,?,?,?)`)
  const insertFts = db.prepare(`INSERT INTO payload_fts (category, file, title, content, keywords) VALUES (?,?,?,?,?)`)

  const files = walkMarkdown(dir)
  let count = 0
  const tx = db.transaction(() => {
    for (const f of files) {
      try {
        const rel = path.relative(dir, f)
        const category = rel.split(path.sep)[0] || 'General'
        const content = fs.readFileSync(f, 'utf8')
        if (content.length < 40) continue
        const title = extractTitle(content) || path.basename(f, '.md')
        const keywords = extractKeywords(content)
        const trimmed = content.slice(0, 20000) // cap per-doc
        insertMeta.run(category, rel, title, trimmed, keywords)
        insertFts.run(category, rel, title, trimmed, keywords)
        count++
      } catch { /* skip unreadable */ }
    }
  })
  tx()
  ftsReady = true
  onLog('info', `Payload RAG index built: ${count} documents across ${VULN_TYPE_MAP ? Object.keys(VULN_TYPE_MAP).length : 0} categories`)
  return { indexed: count }
}

export function payloadsIndexStatus() {
  const dir = config.payloads.dir
  const installed = fs.existsSync(dir)
  let docs = 0
  try { docs = getDb().prepare(`SELECT COUNT(*) c FROM payload_index`).get().c } catch { docs = 0 }
  let categories = []
  if (installed) {
    try {
      categories = fs.readdirSync(dir, { withFileTypes: true })
        .filter(d => d.isDirectory() && !d.name.startsWith('.') && !d.name.startsWith('_'))
        .map(d => d.name)
    } catch { /* ignore */ }
  }
  return { installed, path: dir, docs, categories, ftsReady }
}

/**
 * Retrieve ranked PoC payloads for a vulnerability type.
 * Uses FTS5 MATCH when available, falls back to category mapping + LIKE.
 */
export function retrievePayloads(vulnerabilityType, { limit = 6 } = {}) {
  const status = payloadsIndexStatus()
  if (!status.installed) return { found: false, payloads: [], source: status.path, error: 'corpus-missing' }

  const query = (vulnerabilityType || '').toLowerCase().trim()
  if (!query) return { found: false, payloads: [], source: status.path }

  // 1. Resolve candidate categories via map
  let cats = []
  for (const [k, v] of Object.entries(VULN_TYPE_MAP)) {
    if (query.includes(k)) cats.push(...v)
  }
  cats = [...new Set(cats)]

  const db = getDb()
  let rows = []

  // 2. FTS5 ranked search (best signal)
  if (status.docs > 0) {
    const ftsQuery = buildFtsQuery(query)
    if (ftsQuery) {
      try {
        rows = db.prepare(
          `SELECT category, file, title, content, bm25(payload_fts) AS rank
           FROM payload_fts WHERE payload_fts MATCH ? ORDER BY rank LIMIT ?`
        ).all(ftsQuery, limit * 2)
      } catch { rows = [] }
    }
  }

  // 3. Fallback / augment with category LIKE if FTS weak
  if (rows.length < limit && status.docs > 0 && cats.length) {
    const likeRows = []
    for (const c of cats) {
      try {
        const r = db.prepare(
          `SELECT category, file, title, content, 0 AS rank FROM payload_index WHERE category = ? LIMIT ?`
        ).all(c, limit)
        likeRows.push(...r)
      } catch { /* ignore */ }
    }
    rows = dedupe([...rows, ...likeRows])
  }

  rows = rows.slice(0, limit)

  const payloads = rows.map(r => ({
    category: r.category,
    file: r.file,
    title: r.title,
    snippets: extractCodeSnippets(r.content, 5),
  })).filter(p => p.snippets.length > 0)

  return {
    found: payloads.length > 0,
    payloads,
    matchedCategories: cats,
    source: status.path,
    retrieval: status.docs > 0 ? 'fts5' : 'category',
  }
}

/** Enrich a finding with PoC evidence from the RAG store. */
export function crossReference(finding) {
  if (!finding) return finding
  const term = [finding.title, finding.cweId, (finding.description || '').slice(0, 120)].filter(Boolean).join(' ')
  const res = retrievePayloads(term, { limit: 3 })
  if (res.found) {
    return {
      ...finding,
      poc: {
        source: 'PayloadsAllTheThings',
        retrieval: res.retrieval,
        matchedCategories: res.matchedCategories,
        references: res.payloads.map(p => ({ category: p.category, file: p.file, title: p.title, samples: p.snippets.slice(0, 3) })),
      },
    }
  }
  return finding
}

// ── helpers ──────────────────────────────────────────────────────────────────
function walkMarkdown(root, maxDepth = 3) {
  const out = []
  const rec = (d, depth) => {
    if (depth > maxDepth) return
    let entries
    try { entries = fs.readdirSync(d, { withFileTypes: true }) } catch { return }
    for (const e of entries) {
      const full = path.join(d, e.name)
      if (e.isDirectory() && !e.name.startsWith('.') && !e.name.startsWith('_')) rec(full, depth + 1)
      else if (e.isFile() && /\.(md|txt)$/i.test(e.name)) out.push(full)
    }
  }
  rec(root, 0)
  return out
}

function extractTitle(content) {
  const m = content.match(/^#\s+(.+)$/m)
  return m ? m[1].trim() : null
}

function extractKeywords(content) {
  const heads = [...content.matchAll(/^#{1,3}\s+(.+)$/gm)].map(m => m[1].toLowerCase())
  return [...new Set(heads)].slice(0, 30).join(' ')
}

function buildFtsQuery(query) {
  const tokens = query.replace(/[^\w\s-]/g, ' ').split(/\s+/).filter(t => t.length > 2).slice(0, 6)
  if (!tokens.length) return null
  return tokens.map(t => `"${t}"`).join(' OR ')
}

function extractCodeSnippets(content, max = 5) {
  const out = []
  // CRLF-tolerant fenced-code extraction
  const re = /```[^\r\n]*\r?\n([\s\S]*?)```/g
  let m
  while ((m = re.exec(content)) !== null && out.length < max) {
    const code = m[1].trim()
    if (code.length > 3 && code.length < 1500 && !/^https?:\/\//i.test(code)) out.push(code)
  }
  // Fallback: if no fenced blocks, harvest likely payload lines
  if (!out.length) {
    const interesting = /(select|union|insert|update|delete|or\s+1=1|'|--|\/\*|\{\{|<script|alert\(|\$\{|passwd|etc\/|cmd|exec|system|sleep\(|benchmark|load_file|@@|char\(|concat)/i
    const lines = content.split(/\r?\n/).map(l => l.trim())
      .filter(l => l.length > 4 && l.length < 200 && interesting.test(l) && !/^#/.test(l) && !/^https?:\/\//.test(l))
    for (const l of lines.slice(0, max)) out.push(l)
  }
  return out
}

function dedupe(rows) {
  const seen = new Set()
  return rows.filter(r => {
    const k = `${r.category}|${r.file}`
    if (seen.has(k)) return false
    seen.add(k)
    return true
  })
}

export default { buildPayloadIndex, retrievePayloads, crossReference, payloadsIndexStatus }
