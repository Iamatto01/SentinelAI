// Negative control for audit_layout.py.
//
// Builds the exact defect the SIMPLE cover page once had (a panel drawn before
// the banner that paints over it) plus a card whose body escapes its own frame,
// then _negcheck.py proves the gate fires on it and stays silent on a clean twin.
// A gate that has never failed is not a gate.
//
//   node _negcover.mjs bad  _neg_bad.pdf
//   node _negcover.mjs good _neg_good.pdf
import PDFDocument from 'pdfkit'
import fs from 'node:fs'

const good = process.argv[2] === 'good'
const doc = new PDFDocument({ size: 'A4', margins: { top: 45, bottom: 45, left: 40, right: 40 } })
doc.pipe(fs.createWriteStream(process.argv[3]))

if (!good) {
  // orphaned panel, painted before the banner exists
  doc.rect(40, 45, 515.3, 62).fill('#F0F9FF')
  doc.fillColor('#0F172A').fontSize(9).text('Evidence validation buried under the banner', 48, 53)
}
doc.rect(0, 0, doc.page.width, 135).fill('#0F172A')
doc.fillColor('#FFFFFF').fontSize(20).text('COVER TITLE', 40, 50)

// card whose content runs past its bottom edge (clean twin keeps it inside)
const top = 200
doc.roundedRect(40, top, 515.3, 50, 6).fillAndStroke('#FFFFFF', '#BAE6FD')
doc.fillColor('#0F172A').fontSize(8.5)
doc.text('this body line escapes the card frame', 48, good ? top + 18 : top + 52, { width: 500 })

doc.end()
