// Exercises the shipped title/narrative normalisers in report.js.
//
// report.js pulls in pdfkit and the agents loader, so it cannot be imported in
// isolation. The functions are lifted from source by brace-matching and rebuilt
// with `new Function` — assertions therefore run against the real shipped
// bodies, never a hand-copied duplicate that could drift.
import { readFileSync } from 'node:fs'

const src = readFileSync(new URL('./report.js', import.meta.url), 'utf8')

function extractFn(name) {
  const start = src.indexOf(`function ${name}(`)
  if (start < 0) throw new Error(`not found: ${name}`)
  let depth = 0
  for (let j = src.indexOf('{', start); j < src.length; j++) {
    if (src[j] === '{') depth++
    else if (src[j] === '}') { depth--; if (depth === 0) return src.slice(start, j + 1) }
  }
  throw new Error(`unbalanced: ${name}`)
}

// Mirrors the shipped sanitiser closely enough for these cases: drop non-printable
// characters, keep newlines, trim. Deliberately does NOT strip brackets — the log
// filter must see `[INFO]` intact, and an earlier version of this harness masked
// that by removing them.
const sanitizePdfText = (v) => String(v ?? '').replace(/[^\x20-\x7E\n]/g, '').trim()

const reportFindingTitle = new Function('sanitizePdfText',
  `${extractFn('reportFindingTitle')}; return reportFindingTitle`)(sanitizePdfText)
const cleanReportNarrative = new Function('sanitizePdfText',
  `${extractFn('cleanReportNarrative')}; return cleanReportNarrative`)(sanitizePdfText)

let pass = 0, fail = 0
const check = (label, got, want) => {
  if (Object.is(got, want)) pass++
  else { fail++; console.log(`FAIL ${label}: got ${JSON.stringify(got)} want ${JSON.stringify(want)}`) }
}

console.log('\nreportFindingTitle')

// Version-audit findings get a synthesised, product-named title.
check('version-audit synthesises product title',
  reportFindingTitle({ module: 'version-audit', title: 'junk', evidence: { product: 'nginx', version: '1.18.0' } }),
  'nginx 1.18.0 Outdated or Unsupported')

// Leading severity brackets and warnings are stripped.
check('strips leading [HIGH] tag',
  reportFindingTitle({ title: '[HIGH] SQL Injection' }), 'SQL Injection')

check('strips leading severity prefix',
  reportFindingTitle({ title: 'Warning: exposed .env' }), 'exposed .env')

// A trailing parenthesised URL is boilerplate, not part of the finding name.
check('strips trailing (url)',
  reportFindingTitle({ title: 'Admin panel exposed (https://x.com/admin)' }), 'Admin panel exposed')

check('strips trailing (bare host)',
  reportFindingTitle({ title: 'Admin panel exposed (x.com/admin)' }), 'Admin panel exposed')

check('collapses internal whitespace',
  reportFindingTitle({ title: 'A    B' }), 'A B')

// Never render an empty heading.
check('empty title falls back', reportFindingTitle({ title: '' }), 'Security Finding')
check('missing title falls back', reportFindingTitle({}), 'Security Finding')

console.log('\ncleanReportNarrative')

// Log noise and JSON blobs must not leak into prose.
check('drops timestamped log lines',
  cleanReportNarrative('Real sentence.\n2026-01-01T10:00:00Z noise'), 'Real sentence.')

check('drops raw JSON lines',
  cleanReportNarrative('Real sentence.\n{"a":1}'), 'Real sentence.')

check('joins remaining lines with a space',
  cleanReportNarrative('One.\nTwo.'), 'One. Two.')

check('empty input uses fallback', cleanReportNarrative('', 'fallback'), 'fallback')

check('whitespace-only input uses fallback', cleanReportNarrative('   \n  ', 'fallback'), 'fallback')

// Bare level words, in any case, optionally separated.
check('drops bare lowercase level word',
  cleanReportNarrative('Real sentence.\ninfo: chatter'), 'Real sentence.')
check('drops bare uppercase level word',
  cleanReportNarrative('Real sentence.\nERROR something'), 'Real sentence.')

// Bracketed level tags. Regression guard: a combined
// `^(?:\[[^\]]+\]\s*)?(?:LEVEL)\b` pattern fails here, because the optional tag
// group consumes `[INFO] ` and then demands a level word from `chatter`.
check('drops bracketed log levels',
  cleanReportNarrative('Real sentence.\n[INFO] chatter'), 'Real sentence.')
check('drops bracketed uppercase WARN',
  cleanReportNarrative('Real sentence.\n[WARN] only noise'), 'Real sentence.')
check('drops bracketed lowercase tag',
  cleanReportNarrative('Real sentence.\n[info] chatter'), 'Real sentence.')
check('drops bracketed long level',
  cleanReportNarrative('Real sentence.\n[CRITICAL] disk full'), 'Real sentence.')

// Timestamped log lines, with and without a bracketed tag.
check('drops timestamped line with tag',
  cleanReportNarrative('Real sentence.\n2026-01-01T10:00:00Z [INFO] wait'), 'Real sentence.')
check('drops bare clock-time log line',
  cleanReportNarrative('Real sentence.\n10:00:01 [INFO] wait'), 'Real sentence.')

// A bracketed tag whose contents are not a level word is a heading, not noise.
check('keeps non-level bracketed heading',
  cleanReportNarrative('[Overview] Ports 80 and 443 are open'),
  '[Overview] Ports 80 and 443 are open')

check('all-noise input uses fallback',
  cleanReportNarrative('[WARN] only noise', 'fallback'), 'fallback')

check('mixed noise still yields the real sentence',
  cleanReportNarrative('[INFO] start\nReal sentence.\n[ERROR] boom', 'fallback'), 'Real sentence.')

console.log(`\nreport-helpers: ${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
