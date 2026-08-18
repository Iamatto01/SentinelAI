// Diagnose stuck exploit campaigns
import Database from 'better-sqlite3'

const db = new Database('f:/FYP2PROJECT/output/fyp2.db', { readonly: true })

const byStatus = db.prepare(`SELECT status, COUNT(*) n FROM exploit_campaigns GROUP BY status`).all()
console.log('Campaigns by status:', JSON.stringify(byStatus, null, 2))

const stuck = db.prepare(`
  SELECT c.id, c.status, c.risk_level, c.created_at,
    (SELECT COUNT(*) FROM exploit_steps s WHERE s.campaign_id = c.id) AS total_steps,
    (SELECT COUNT(*) FROM exploit_steps s WHERE s.campaign_id = c.id AND s.status = 'awaiting_approval') AS gated_steps,
    (SELECT COUNT(*) FROM exploit_steps s WHERE s.campaign_id = c.id AND s.status = 'pending') AS pending_steps,
    (SELECT COUNT(*) FROM exploit_approvals a WHERE a.campaign_id = c.id AND a.status = 'pending') AS pending_approvals
  FROM exploit_campaigns c
  WHERE c.status IN ('awaiting_approval', 'queued', 'running', 'paused')
`).all()
console.log('Active/stuck campaigns:', JSON.stringify(stuck, null, 2))

const stepStatus = db.prepare(`SELECT status, COUNT(*) n FROM exploit_steps GROUP BY status`).all()
console.log('Steps by status:', JSON.stringify(stepStatus, null, 2))

db.close()
