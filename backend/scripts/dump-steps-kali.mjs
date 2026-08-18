// Dump finding evidence for a campaign
import Database from 'better-sqlite3'

const db = new Database('/home/kali/SentinelAI/output/fyp2.db', { readonly: true })
const cid = process.argv[2] || 'camp_887c3039-a528-4e1e-b37e-62985d99efc4'
const c = db.prepare(`SELECT finding_id FROM exploit_campaigns WHERE id = ?`).get(cid)
if (c?.finding_id) {
  const f = db.prepare(`SELECT * FROM findings WHERE id = ?`).get(c.finding_id)
  console.log('title:', f.title)
  const cols = Object.keys(f).filter(k => ['target','module','cve_id','url','host'].includes(k))
  cols.forEach(k => console.log(k + ':', f[k]))
  console.log('evidence:', (f.evidence || '').slice(0, 600))
  console.log('poc:', (f.poc || '').slice(0, 400))
}
db.close()
