import fs from 'fs'
import zlib from 'zlib'

function hexToText(hex) {
  const clean = hex.replace(/\s+/g, '')
  let out = ''
  for (let i = 0; i + 1 < clean.length; i += 2) out += String.fromCharCode(parseInt(clean.slice(i, i + 2), 16))
  return out
}

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
    try { chunks.push(zlib.inflateSync(raw).toString('latin1')) } catch { /* uncompressed */ }
    i = e + 9
  }
  const text = []
  for (const chunk of chunks) {
    const re = /\[((?:[^\[\]]|\\.)*)\]\s*TJ|<([0-9A-Fa-f\s]+)>\s*Tj|\((?:\\.|[^\\()])*\)\s*Tj/g
    let m
    while ((m = re.exec(chunk))) {
      if (m[1] !== undefined) {
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
  return text.join('\n')
}

const file = process.argv[2]
if (!file) {
  console.error('Specify file')
  process.exit(1)
}
const text = pdfText(file)
fs.writeFileSync('backend/scripts/extracted_report_text.txt', text, 'utf-8')
console.log(`Extracted ${text.length} characters to backend/scripts/extracted_report_text.txt`)
