import fs from 'node:fs'
import path from 'node:path'
import { getDb } from '../db.js'
import { config } from '../config.js'

/**
 * Cybersecurity Skills RAG engine (Anthropic-Cybersecurity-Skills corpus).
 *
 * Implements the "index.md lazy-loading" pattern as a machine-readable index:
 * instead of loading all 817 SKILL.md files into the LLM context, we build a
 * persistent FTS5 index of frontmatter (name, description, tags, subdomain)
 * and only load the FULL markdown body of the 1-3 best-matching skills when
 * a finding is analyzed. This keeps DeepSeek prompts small and relevant.
 *
 * Corpus: https://github.com/mukul975/Anthropic-Cybersecurity-Skills (Apache-2.0)
 */

let ftsReady = false

/** Parse YAML-ish frontmatter without a YAML dependency (fields we care about). */
function parseFrontmatter(content) {
  const fm = {}
  const m = content.match(/^---\r?\n([\s\S]*?)\r?\n---/)
  if (!m) return fm
  const yaml = m[1]
  // Simple scalars: name:, subdomain:, version:
  for (const key of ['name', 'subdomain', 'domain', 'version']) {
    const km = yaml.match(new RegExp(`^${key}:\\s*(.+)$`, 'm'))
    if (km) fm[key] = km[1].trim().replace(/^['"]|['"]$/g, '')
  }
  // description: may be a folded block (>-) spanning lines
  const dm = yaml.match(/^description:\s*>-?\s*\n((?:\s+.+\n?)+)/m)
  if (dm) fm.description = dm[1].replace(/\s+/g, ' ').trim()
  else {
    const ds = yaml.match(/^description:\s*'?(.+?)'?\s*$/m)
    if (ds) fm.description = ds[1].trim()
  }
  // list fields: tags:, mitre_attack:, nist_csf:, atlas_techniques:, d3fend_techniques:
  for (const key of ['tags', 'mitre_attack', 'nist_csf', 'atlas_techniques', 'd3fend_techniques', 'nist_ai_rmf', 'mitre_f3']) {
    const items = []
    // inline list: [a, b, c]
    const il = yaml.match(new RegExp(`^${key}:\\s*\\[(.*)\\]`, 'm'))
    if (il) il[1].split(',').forEach(s => { const v = s.trim().replace(/^['"]|['"]$/g, ''); if (v) items.push(v) })
    else {
      // block list:
      const bl = yaml.match(new RegExp(`^${key}:\\s*(?:#.*)?$((?:\\n\\s*-\\s*.+)*)`, 'm'))
      if (bl) {
        for (const lm of bl[1].matchAll(/^\s*-\s*(.+)$/gm)) {
          const v = lm[1].trim().replace(/^['"]|['"]$/g, '')
          if (v) items.push(v)
        }
      }
    }
    if (items.length) fm[key] = items
  }
  return fm
}

/** Extract the markdown body (everything after frontmatter), trimmed & capped. */
function extractBody(content, cap = 12000) {
  const m = content.match(/^---\r?\n[\s\S]*?\r?\n---\r?\n?/)
  const body = m ? content.slice(m[0].length) : content
  return body.trim().slice(0, cap)
}

/** Build (or rebuild) the persistent skills index from the corpus. */
export function buildSkillsIndex(onLog = () => {}) {
  const dir = config.skills.dir
  if (!fs.existsSync(dir)) {
    onLog('warn', `Skills corpus not found at ${dir}`)
    return { indexed: 0, subdomains: [] }
  }
  const db = getDb()

  db.exec(`DROP TABLE IF EXISTS skills_fts;`)
  db.exec(`CREATE VIRTUAL TABLE skills_fts USING fts5(name, subdomain, description, tags, body, frameworks);`)
  db.exec(`DELETE FROM skills_index;`)

  const insertMeta = db.prepare(`INSERT OR REPLACE INTO skills_index (name, subdomain, description, tags, frameworks, file, body) VALUES (?,?,?,?,?,?,?)`)
  const insertFts = db.prepare(`INSERT INTO skills_fts (name, subdomain, description, tags, body, frameworks) VALUES (?,?,?,?,?,?)`)

  let count = 0
  const subdomains = new Set()
  const tx = db.transaction(() => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (!entry.isDirectory() || entry.name.startsWith('.')) continue
      const skillPath = path.join(dir, entry.name, 'SKILL.md')
      if (!fs.existsSync(skillPath)) continue
      try {
        const content = fs.readFileSync(skillPath, 'utf8')
        if (content.length < 60) continue
        const fm = parseFrontmatter(content)
        const name = fm.name || entry.name
        const subdomain = fm.subdomain || 'general'
        const description = (fm.description || '').slice(0, 1200)
        const tags = (fm.tags || []).join(' ')
        const frameworks = [
          ...(fm.mitre_attack || []).join(' '),
          ...(fm.nist_csf || []).join(' '),
          ...(fm.atlas_techniques || []).join(' '),
          ...(fm.d3fend_techniques || []).join(' '),
          ...(fm.nist_ai_rmf || []).join(' '),
          ...(fm.mitre_f3 || []).join(' '),
        ].join(' ')
        const body = extractBody(content)
        subdomains.add(subdomain)
        insertMeta.run(name, subdomain, description, tags, frameworks, path.join(entry.name, 'SKILL.md'), body)
        insertFts.run(name, subdomain, description, tags, body, frameworks)
        count++
      } catch { /* skip unreadable skill */ }
    }
  })
  tx()
  ftsReady = true
  onLog('info', `Skills index built: ${count} skills across ${subdomains.size} subdomains`)
  return { indexed: count, subdomains: [...subdomains].sort() }
}

export function skillsIndexStatus() {
  const dir = config.skills.dir
  const installed = fs.existsSync(dir)
  let skills = 0
  let subdomains = []
  try {
    const db = getDb()
    skills = db.prepare(`SELECT COUNT(*) c FROM skills_index`).get().c
    subdomains = db.prepare(`SELECT subdomain, COUNT(*) n FROM skills_index GROUP BY subdomain ORDER BY n DESC`).all().map(r => `${r.subdomain} (${r.n})`)
  } catch { /* table may not exist yet */ }
  return { installed, path: dir, skills, subdomains, ftsReady }
}

/**
 * Retrieve the most relevant skills for a finding / query.
 * Returns full bodies (for LLM injection) of the top matches.
 */
export function retrieveSkills(query, { limit = 2, includeBody = true } = {}) {
  const status = skillsIndexStatus()
  if (!status.installed || status.skills === 0) return { found: false, skills: [], source: status.path }

  const q = (query || '').toLowerCase().trim()
  if (!q) return { found: false, skills: [], source: status.path }

  const db = getDb()
  let rows = []

  // Tiered FTS5: strict AND first, then relaxed OR. bm25 weights prioritize
  // name/tag matches over body matches for precision.
  for (const ftsQuery of buildFtsQueries(q)) {
    if (rows.length) break
    try {
      rows = db.prepare(
        `SELECT name, subdomain, description, tags, body, bm25(skills_fts, 8.0, 2.0, 3.0, 4.0, 0.5, 1.0) AS rank
         FROM skills_fts WHERE skills_fts MATCH ? ORDER BY rank LIMIT ?`
      ).all(ftsQuery, limit)
    } catch { rows = [] }
  }

  // Fallback: LIKE on description/tags
  if (!rows.length) {
    const tokens = q.replace(/[^\w\s]/g, ' ').split(/\s+/).filter(t => t.length > 3).slice(0, 3)
    for (const t of tokens) {
      try {
        const r = db.prepare(
          `SELECT name, subdomain, description, tags, body, 0 AS rank FROM skills_index
           WHERE description LIKE ? OR tags LIKE ? OR name LIKE ? LIMIT ?`
        ).all(`%${t}%`, `%${t}%`, `%${t}%`, limit)
        rows.push(...r)
      } catch { /* ignore */ }
    }
    // dedupe
    const seen = new Set()
    rows = rows.filter(r => (seen.has(r.name) ? false : (seen.add(r.name), true)))
    rows = rows.slice(0, limit)
  }

  return {
    found: rows.length > 0,
    skills: rows.map(r => ({
      name: r.name,
      subdomain: r.subdomain,
      description: r.description,
      tags: r.tags,
      body: includeBody ? r.body : undefined,
    })),
    source: status.path,
    retrieval: 'fts5',
  }
}

/**
 * Build the "index.md" catalog — a human/machine-readable lazy-load map of
 * every skill (name, subdomain, description one-liner, file path). Written to
 * knowledge/skills/index.md so agents can scan the catalog without reading
 * all 817 files.
 */
export function writeSkillsCatalog() {
  const dir = config.skills.dir
  const db = getDb()
  let rows = []
  try {
    rows = db.prepare(`SELECT name, subdomain, description, file FROM skills_index ORDER BY subdomain, name`).all()
  } catch { /* index not built */ }
  if (!rows.length) return { written: false, count: 0 }

  const bySub = {}
  for (const r of rows) (bySub[r.subdomain] = bySub[r.subdomain] || []).push(r)

  let md = `# Cybersecurity Skills Index (lazy-load catalog)\n\n`
  md += `> Auto-generated by SentinelAI skills-rag. Do not edit by hand.\n`
  md += `> Corpus: mukul975/Anthropic-Cybersecurity-Skills (Apache-2.0) — ${rows.length} skills.\n`
  md += `> Pattern: scan THIS catalog first, then read only the SKILL.md files relevant to the task.\n\n`
  md += `## Usage\n\n\`\`\`\n1. Find the relevant subdomain section below (or grep this file for a keyword).\n2. Open only the listed SKILL.md path(s) for full workflow, prerequisites, commands.\n\`\`\`\n\n`

  for (const sub of Object.keys(bySub).sort()) {
    md += `## ${sub} (${bySub[sub].length})\n\n`
    md += `| Skill | Description | File |\n|---|---|---|\n`
    for (const s of bySub[sub]) {
      const desc = (s.description || '').replace(/\|/g, '\\|').slice(0, 140)
      md += `| ${s.name} | ${desc} | ${s.file} |\n`
    }
    md += `\n`
  }

  const out = path.join(dir, 'index.md')
  fs.writeFileSync(out, md, 'utf8')
  return { written: true, count: rows.length, path: out }
}

// ── helpers ──────────────────────────────────────────────────────────────────
const STOPWORDS = new Set(['the', 'and', 'for', 'with', 'that', 'this', 'from', 'into', 'your', 'you', 'are', 'was', 'has', 'have', 'not', 'can', 'may', 'via', 'using', 'when', 'which', 'what', 'how'])

function tokenize(query) {
  return [...new Set(
    query.toLowerCase().replace(/[^\w\s.-]/g, ' ').split(/\s+/)
      .filter(t => t.length > 2 && !STOPWORDS.has(t) && !/^\d+$/.test(t))
  )].slice(0, 8)
}

/** Tiered FTS queries: strict AND (all tokens) → pairwise AND → relaxed OR. */
function buildFtsQueries(query) {
  const tokens = tokenize(query)
  if (!tokens.length) return []
  const queries = []
  if (tokens.length > 1) queries.push(tokens.map(t => `"${t}"`).join(' AND '))
  // pairwise AND for key-term co-occurrence
  for (let i = 0; i < tokens.length - 1 && queries.length < 4; i++) {
    queries.push(`"${tokens[i]}" AND "${tokens[i + 1]}"`)
  }
  queries.push(tokens.map(t => `"${t}"`).join(' OR '))
  return queries
}

export default { buildSkillsIndex, skillsIndexStatus, retrieveSkills, writeSkillsCatalog }
