import { all } from './src/db.js'
const MAXV = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H'
const rows = all(`SELECT severity, cvss, cvss_vector, title FROM findings`)
const play = rows.filter((r) => r.scan_id !== '__x__')
console.log('severity histogram:')
for (const [k, v] of Object.entries(rows.reduce((a, r) => (a[r.severity] = (a[r.severity] || 0) + 1, a), {})).sort((a,b)=>b[1]-a[1])) console.log(`  ${k.padEnd(9)} ${v}`)
const at10 = rows.filter((r) => Number(r.cvss) >= 9.95)
console.log(`\nrows scoring 10.0: ${at10.length}`)
for (const r of at10) console.log(`  ${r.severity.padEnd(8)} ${r.cvss}  ${String(r.title).slice(0, 68)}`)
const critical = rows.filter((r) => r.severity === 'critical')
console.log(`\ncritical rows: ${critical.length} (of ${rows.length})`)
const mism = rows.filter((r) => {
  const s = Number(r.cvss)
  const want = s >= 9.0 ? 'critical' : s >= 7.0 ? 'high' : s >= 4.0 ? 'medium' : s > 0 ? 'low' : 'info'
  return want !== r.severity
})
console.log(`label/score disagreements: ${mism.length}`)
for (const r of mism.slice(0, 5)) console.log(`  ${r.severity} ${r.cvss} ${String(r.title).slice(0, 50)}`)

// ── Export parity (static contract) ──
// The full report once rendered no technology inventory at all, so the
// "authoritative" export was the one that never cited a CVE: generateReport
// built techStack, passed it to the simplified renderer, and dropped it on the
// floor for renderPdf. Assert the wiring, so deleting either half fails here
// instead of silently shipping a CVE-free full report again.
// (Text-level parity — that the CVEs actually reach the page — is checked in
// audit_layout.py, which can decode the PDF's CID-encoded text.)
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const reportSrc = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'src', 'report.js'), 'utf8',
)
// Scope each assertion to the function that must contain it. A whole-file regex
// would stay green if the call drifted into the wrong renderer, which is exactly
// the shape of the bug: the inventory existed, just not in the full report.
const sliceFn = (start, end) => {
  const a = reportSrc.indexOf(start)
  if (a < 0) return ''
  const b = end ? reportSrc.indexOf(end, a + 1) : -1
  return reportSrc.slice(a, b < 0 ? reportSrc.length : b)
}
const renderPdfBody = sliceFn('async function renderPdf({', 'async function renderSimplifiedPdf(')
const reportBody = sliceFn('export async function generateReport(', 'export async function generateProjectReport(')
const projectBody = sliceFn('export async function generateProjectReport(', 'async function renderPdf({')

const parity = [
  ['renderTechInventory is defined', /function renderTechInventory\s*\(/.test(reportSrc)],
  ['renderPdf calls renderTechInventory', /renderTechInventory\(doc, \{ techStack \}\)/.test(renderPdfBody)],
  ['renderPdf accepts techStack', /async function renderPdf\(\{[^)]*techStack = null/.test(reportSrc)],
  ['generateReport passes techStack to renderPdf', /renderPdf\(\{\s*\n\s*file, reportTitle, scans, project, vulnerabilities: reportFindings[\s\S]{0,400}?verificationSummary, techStack,/.test(reportBody)],
  ['generateReport passes techStack to renderSimplifiedPdf', /renderSimplifiedPdf\(\{[\s\S]{0,500}?\n\s*techStack,/.test(reportBody)],
  ['generateProjectReport builds a fingerprint', /buildTechStackFingerprint\(activeFindings\)/.test(projectBody)],
  ['generateProjectReport refreshes it against NVD', /refreshUncorrelatedComponents\(techStack,/.test(projectBody)],
  ['generateProjectReport passes techStack to renderPdf', /verificationSummary, techStack,/.test(projectBody)],
]
console.log('\nexport parity:')
let parityFail = 0
for (const [label, ok] of parity) {
  console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${label}`)
  if (!ok) parityFail++
}
if (parityFail) process.exitCode = 1
