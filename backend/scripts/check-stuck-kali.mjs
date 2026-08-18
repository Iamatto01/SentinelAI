// Deep-dive: all campaigns + approvals + step outputs
import Database from 'better-sqlite3'

const db = new Database('/home/kali/SentinelAI/output/fyp2.db', { readonly: true })

const done = db.prepare(`SELECT id, status, risk_level, created_at, finished_at, finding_id FROM exploit_campaigns ORDER BY created_at DESC`).all()
console.log('All campaigns:', JSON.stringify(done, null, 1))

for (const c of done.slice(0, 4)) {
  const steps = db.prepare(`SELECT step_order, step_type, tool_name, status, needs_approval, started_at, finished_at, length(output) AS out_len, substr(output,1,300) AS out300 FROM exploit_steps WHERE campaign_id = ? ORDER BY step_order`).all(c.id)
  console.log(`\n=== ${c.id} [${c.status}] created=${c.created_at} finished=${c.finished_at}`)
  for (const s of steps) {
    console.log(`  ${s.step_order}. ${s.tool_name} [${s.status}] gate=${s.needs_approval} started=${s.started_at} fin=${s.finished_at}`)
    if (s.out300) console.log(`     out: ${s.out300.replace(/\n/g, ' | ').slice(0, 280)}`)
  }
  const apps = db.prepare(`SELECT * FROM exploit_approvals WHERE campaign_id = ?`).all(c.id)
  console.log('  approvals:', JSON.stringify(apps, null, 1))
}

try {
  const logs = db.prepare(`SELECT COUNT(*) n FROM exploit_logs`).all()
  console.log('\nexploit_logs count:', JSON.stringify(logs))
} catch (e) { console.log('\nexploit_logs table:', e.message) }
db.close()
