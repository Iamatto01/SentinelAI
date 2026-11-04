import fs from 'fs'

const txt = fs.readFileSync('backend/scripts/extracted_report_text.txt', 'utf8')
const lines = txt.split('\n')

const start = lines.findIndex(l => l.includes('5. Issue Classification'))
const end = lines.findIndex(l => l.includes('6. Detailed Findings'))
const tableLines = lines.slice(start, end)
const items = []
for (let i = 0; i < tableLines.length; i++) {
  const line = tableLines[i].trim()
  if (/^\d+$/.test(line) && i + 5 < tableLines.length) {
    const num = line
    const title = tableLines[i+1].trim()
    const cat = tableLines[i+2].trim()
    const sev = tableLines[i+3].trim()
    const seen = tableLines[i+4].trim()
    const ver = tableLines[i+5].trim()
    if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(sev)) {
      items.push({ num, title, cat, sev, seen, ver })
    }
  }
}
console.log('Total parsed items:', items.length)
for (const it of items) {
  console.log(`#${it.num.padEnd(2)} [${it.sev.padEnd(8)}] [${it.ver.padEnd(9)}] ${it.title}`)
}
