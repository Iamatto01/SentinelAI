/**
 * Backfill persisted severity/cvss/cvss_vector for findings stored before the
 * CVSS v4.0 authority existed. Without this the PDF prints a reconciled score
 * while the API and the database still serve the fabricated declared one.
 *
 *   node reconcile_stored.mjs           # dry run, reports what would change
 *   node reconcile_stored.mjs --apply   # writes the reconciled values
 */
import { all, run } from './src/db.js'
import { evaluateFindingCvss } from './src/cvss4.js'

const apply = process.argv.includes('--apply')


const rows = all(`SELECT id, scan_id, title, severity, cvss, cvss_vector, module, cwe_id AS cweId, evidence, description FROM findings`)
let changed = 0
let unchanged = 0
let declareOnly = 0
const byClass = new Map()
const severityFlips = new Map()

for (const row of rows) {
  let evidence = {}
  try { evidence = JSON.parse(row.evidence || '{}') } catch { evidence = {} }
  const finding = {
    title: row.title,
    severity: row.severity,
    cvss: row.cvss,
    cvssVector: row.cvss_vector,
    cwe: row.cweId,
    module: row.module,
    description: row.description,
    evidence,
  }

  const evaluation = evaluateFindingCvss(finding)
  const before = { severity: row.severity, score: Number(row.cvss) || 0, vector: row.cvss_vector }
  const after = { severity: evaluation.severity, score: evaluation.score, vector: evaluation.vector }
  const same = before.severity === after.severity
    && Math.abs(before.score - after.score) < 1e-9
    && before.vector === after.vector

  if (same) { unchanged++; continue }
  changed++
  if (!evaluation.reconciled) declareOnly++

  byClass.set(evaluation.findingClass, (byClass.get(evaluation.findingClass) || 0) + 1)
  const flip = `${before.severity} -> ${after.severity}`
  severityFlips.set(flip, (severityFlips.get(flip) || 0) + 1)

  if (apply) {
    run(
      `UPDATE findings SET severity = ?, cvss = ?, cvss_vector = ? WHERE id = ?`,
      after.severity, after.score, after.vector, row.id,
    )
  }
}

console.log(`rows scanned : ${rows.length}`)
console.log(`already ok   : ${unchanged}`)
console.log(`to rewrite   : ${changed}${declareOnly ? ` (${declareOnly} never declared a vector)` : ''}`)
console.log(apply ? 'STATUS       : APPLIED' : 'STATUS       : dry run — pass --apply to write')
console.log('\nseverity transitions:')
for (const [k, v] of [...severityFlips].sort((a, b) => b[1] - a[1])) console.log(`  ${k.padEnd(28)} ${v}`)
console.log('\ntop classes rewritten:')
for (const [k, v] of [...byClass].sort((a, b) => b[1] - a[1]).slice(0, 12)) console.log(`  ${String(k).padEnd(28)} ${v}`)
