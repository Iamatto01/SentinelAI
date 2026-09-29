/**
 * Purge all client accounts and configure master admin credentials:
 * Username/Email: admin@sentinelai.com
 * Password: kali
 */

import Database from 'better-sqlite3'
import bcrypt from 'bcryptjs'
import fs from 'node:fs'
import path from 'node:path'

const DB_PATH = process.env.DB_PATH || (fs.existsSync('/home/kali/server/SentinelAI_Data/fyp2.db')
  ? '/home/kali/server/SentinelAI_Data/fyp2.db'
  : path.resolve('output/fyp2.db'))

console.log(`\n======================================================`)
console.log(`🛡️  SentinelAI User Reset & Client Purge`)
console.log(`📁 Database Path: ${DB_PATH}`)
console.log(`======================================================\n`)

if (!fs.existsSync(DB_PATH)) {
  console.error(`❌ Database not found at ${DB_PATH}`)
  process.exit(1)
}

const db = new Database(DB_PATH)
db.pragma('journal_mode = WAL')
db.pragma('foreign_keys = OFF') // Temporarily off during clean batch update

const adminId = 'usr_admin_master'
const adminEmail = 'admin@sentinelai.com'
const pentestId = 'usr_pentester_saifudin'
const pentestEmail = 'muhammadsaifudinmj@gmail.com'
const pass = 'kali'
const passHash = bcrypt.hashSync(pass, 10)
const now = new Date().toISOString()

const purgeTx = db.transaction(() => {
  // 1. Delete all users
  const deletedUsers = db.prepare(`DELETE FROM users`).run()
  console.log(`🧹 Purged all previous user accounts (Total purged: ${deletedUsers.changes})`)

  // 2. Insert the 2 master accounts
  const insertUser = db.prepare(`
    INSERT INTO users (id, username, email, password_hash, role, created_at, last_login)
    VALUES (?, ?, ?, ?, 'admin', ?, ?)
  `)
  insertUser.run(adminId, adminEmail, adminEmail, passHash, now, now)
  insertUser.run(pentestId, pentestEmail, pentestEmail, passHash, now, now)

  console.log(`👑 Created Master Accounts:`)
  console.log(`   1. Administrator:         ${adminEmail} / ${pass}`)
  console.log(`   2. Penetration Tester:    ${pentestEmail} / ${pass}`)

  // 3. Clear client_credentials
  const delCreds = db.prepare(`DELETE FROM client_credentials`).run()
  console.log(`🧹 Purged client credentials (Total: ${delCreds.changes})`)

  // 4. Reset subscriptions & assign Enterprise to both accounts
  db.prepare(`DELETE FROM subscriptions`).run()
  db.prepare(`DELETE FROM payment_transactions`).run()
  const insertSub = db.prepare(`
    INSERT INTO subscriptions (id, user_id, plan_id, plan_name, status, scan_quota_total, scan_quota_used, current_period_end, created_at, updated_at)
    VALUES (?, ?, 'enterprise', 'Enterprise Unlimited', 'active', 999999, 0, '2099-12-31T23:59:59.000Z', ?, ?)
  `)
  insertSub.run('sub_admin_master', adminId, now, now)
  insertSub.run('sub_pentest_saifudin', pentestId, now, now)
  console.log(`💳 Configured Enterprise unlimited subscriptions for both master accounts`)

  // 5. Re-link all historical scans and projects to master admin
  const scansUpdated = db.prepare(`UPDATE scans SET user_id = ?, client = 'admin'`).run(adminId)
  const projsUpdated = db.prepare(`UPDATE projects SET user_id = ?`).run(adminId)
  console.log(`🔗 Re-linked and preserved all historical assets:`)
  console.log(`   - Scans preserved & linked:    ${scansUpdated.changes}`)
  console.log(`   - Projects preserved & linked: ${projsUpdated.changes}`)
})

purgeTx()
db.pragma('foreign_keys = ON')

// Verification summary
const totalUsers = db.prepare(`SELECT count(*) as c FROM users`).get().c
const totalScans = db.prepare(`SELECT count(*) as c FROM scans`).get().c
const totalFindings = db.prepare(`SELECT count(*) as c FROM findings`).get().c
const totalProjects = db.prepare(`SELECT count(*) as c FROM projects`).get().c
const totalCreds = db.prepare(`SELECT count(*) as c FROM client_credentials`).get().c
const adminRecord = db.prepare(`SELECT id, username, email, role FROM users WHERE id = ?`).get(adminId)

console.log(`\n======================================================`)
console.log(`📊 FINAL DATABASE STATE:`)
console.log(`   - Total Users:              ${totalUsers} (Admin: ${adminRecord.email})`)
console.log(`   - Total Client Credentials: ${totalCreds}`)
console.log(`   - Total Projects / Folders: ${totalProjects}`)
console.log(`   - Total Historical Scans:   ${totalScans}`)
console.log(`   - Total Findings:           ${totalFindings}`)
console.log(`======================================================\n`)

db.close()
console.log(`✅ All clients removed. Admin credentials are ready (admin@sentinelai.com / kali).\n`)
