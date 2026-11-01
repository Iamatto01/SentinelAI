/**
 * Assert that a generated report actually contains the sections the output
 * contract promises. Renders are only useful if the classification layer reaches
 * the page, so this reads the PDF back instead of trusting the renderer.
 *
 * Usage: node scripts/pdf-text-check.mjs <report.pdf> [--json <counts.json>]
 */
import fs from 'fs'
import zlib from 'zlib'

export function pdfText(file) {
  const buf = fs.readFileSync(file)
  const chunks = []
  let i = 0
  while (true) {
    const s = buf.indexOf('stream', i)
    if (s === -1) break
    let st = s + 6
    if (buf[st] === 0x0d) st++
    if (buf[st] === 0x0a) st++
    const e = buf.indexOf('endstream', st)
    if (e === -1) break
    const raw = buf.subarray(st, e)
    try { chunks.push(zlib.inflateSync(raw).toString('latin1')) } catch { /* uncompressed stream */ }
    i = e + 9
  }
  // pdfkit writes text as hex strings inside TJ/Tj, so both forms must be read.
  const text = []
  for (const chunk of chunks) {
    const re = /\[((?:[^\[\]]|\\.)*)\]\s*TJ|<([0-9A-Fa-f\s]+)>\s*Tj|\((?:\\.|[^\\()])*\)\s*Tj/g
    let m
    while ((m = re.exec(chunk))) {
      if (m[1] !== undefined) {
        // Glyph runs inside one TJ array are one visual string; join them with no separator.
        let line = ''
        for (const part of m[1].matchAll(/<([0-9A-Fa-f\s]+)>|\((?:\\.|[^\\()])*\)/g)) {
          if (part[1] !== undefined) line += hexToText(part[1])
          else line += part[0].slice(1, -1).replace(/\\([()\\])/g, '$1')
        }
        if (line.trim()) text.push(line)
      } else if (m[2] !== undefined) {
        text.push(hexToText(m[2]))
      } else {
        text.push(m[0].slice(1, -1).replace(/\\([()\\])/g, '$1'))
      }
    }
  }
  return text.join(' ')
}

function hexToText(hex) {
  const clean = hex.replace(/\s+/g, '')
  let out = ''
  for (let i = 0; i + 1 < clean.length; i += 2) out += String.fromCharCode(parseInt(clean.slice(i, i + 2), 16))
  return out
}

const file = process.argv[2]
if (!file) { console.error('usage: node scripts/pdf-text-check.mjs <pdf> [--simple]'); process.exit(2) }
if (!fs.existsSync(file)) { console.error('missing file: ' + file); process.exit(2) }

// The two report types make different promises. The full report is an
// engineer deliverable: it must expose every claim and its status. The
// simplified guide is a management deliverable: it must NOT surface an
// unproven lead as something to action, because that is the contradiction
// that makes the whole document untrustworthy.
const simple = process.argv.includes('--simple')
const text = pdfText(file)
const norm = text.replace(/\s+/g, ' ')
const results = []
const has = (label, ...needles) => results.push({
  label,
  ok: needles.every(n => norm.includes(n)),
  missing: needles.filter(n => !norm.includes(n)),
})
// Either wording satisfies "a reproduction hint is present".
const hasAny = (label, ...alts) => results.push({
  label,
  ok: alts.some(a => norm.includes(a)),
  missing: [`one of: ${alts.join(' | ')}`],
})

if (simple) {
  has('evidence validation box', 'Evidence validation')
  has('triage strip', 'What Needs Your Attention')
  has('unverified appendix', 'Unverified')
  has('appendix A heading', 'Appendix A')
  // The simplified report has no per-finding evidence box, so the equivalent
  // promise is the appendix's own warning that leads are not action items.
  hasAny('leads are not action items', 'Not action items', 'Reproduce each lead before treating it as a defect')
  hasAny('reproduction hint', 'To confirm:', 'Reproduce before treating it as a defect')
  has('confirmed count stated', 'confirmed')

  // The defect Jack reported: a lead whose own verdict says "no artifact
  // settles this claim" must not be handed to management as a fix card.
  // Fix cards are numbered; check that no unverified title sits in one.
  // The zone must stop at Appendix A, otherwise a lead legitimately listed
  // there reads as if it had leaked into an action card.
  const cardsStart = norm.indexOf('Your Fix Cards')
  // "Appendix A" first appears in the table of contents, long before the cards,
  // so search forward from the cards instead of trusting the first match.
  const appendixAt = cardsStart === -1 ? -1 : norm.indexOf('Appendix A', cardsStart)
  const cardZone = cardsStart === -1
    ? ''
    : norm.slice(cardsStart, appendixAt > cardsStart ? appendixAt : undefined)
  for (const title of ['Admin panel discovered', 'Reflected XSS in /search']) {
    results.push({
      label: `unverified lead not a fix card: ${title}`,
      ok: !cardZone.includes(title),
      missing: [`${title} must not appear in the action-card zone`],
    })
  }
  // A confirmed finding must arrive with its artifact and a runnable command,
  // not just an assertion that it is real.
  hasAny('captured proof shown on card', 'WHAT WE CAPTURED', 'What we captured')
  hasAny('card carries a runnable command', 'curl -sS', 'nmap -Pn')
} else {
  has('executive summary', 'Executive Summary')
  has('methodology', 'Methodology')
  has('issue classification section', 'Issue Classification')
  has('detailed findings', 'Detailed Findings')
  has('appendix A', 'Unverified')
  has('confirmed status rendered', 'Confirmed')
  has('rejected status rendered', 'Rejected')
  has('occurrence count rendered', '40')
  has('no-artifact disclosure', 'No tool output or HTTP response was captured')
  hasAny('reproduction hint', 'Reproduce before treating it as a defect', 'To confirm:')

  // A rejected claim must not appear as a normal finding with a fix recommendation.
  results.push({
    label: 'rejected XSS not given a remedy',
    ok: !/Reflected XSS in \/search[\s\S]{0,600}?Remediation/.test(norm),
    missing: ['Reflected XSS in /search ... Remediation block'],
  })

  // A persona list proves the platform *can* call a model. This proves it did,
  // and says so plainly when it did not.
  results.push({
    label: 'AI model usage disclosed',
    ok: norm.includes('AI Model Usage') &&
      (/Model calls: \d+/.test(norm) || norm.includes('No language model was reached during this scan')),
    missing: ['AI Model Usage ledger with call count or explicit no-model disclosure'],
  })
  results.push({
    label: 'AI verdicts not claimed as proof',
    ok: /never accepted as proof of exploitability|not applicable/.test(norm),
    missing: ['statement that AI confidence is advisory, not evidence'],
  })
}

let pass = 0, fail = 0
for (const r of results) {
  if (r.ok) { pass++; console.log('  PASS  ' + r.label) }
  else { fail++; console.log('  FAIL  ' + r.label + '  (missing: ' + r.missing.join(', ') + ')') }
}
console.log(`\n${pass}/${pass + fail} PDF assertions passed`)
console.log('report sections present:', norm.includes('Issue Classification') && norm.includes('Unverified'))
process.exit(fail === 0 ? 0 : 1)
