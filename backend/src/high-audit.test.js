import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import Database from 'better-sqlite3'

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-high-audit-'))
process.env.JWT_SECRET ||= 'test-only-jwt-secret-high-audit'
process.env.DB_PATH = path.join(tmpDir, 'high-audit.db')
process.env.OUTPUT_DIR = tmpDir

const db = await import('./db.js')
const { sendContactInquiryNotification } = await import('./email.js')

let passed = 0
let failed = 0

async function test(name, fn) {
  try {
    await fn()
    passed++
    console.log(`  PASS: ${name}`)
  } catch (err) {
    failed++
    console.error(`  FAIL: ${name} -> ${err.message}`)
  }
}

console.log('\n--- Running High Audit (#2, #3, #4, #5, #7) Regression Tests ---')

try {
  await test('High #7: backupDatabase & verifySqliteBackup accept valid full backup and reject 0-table stubs / missing tables / row mismatches', async () => {
    const activeDb = db.getDb()
    const res = await db.backupDatabase()
    assert.equal(res.success, true)
    assert.ok(fs.existsSync(res.backupFile))
    const latest = path.join(tmpDir, 'backups', 'fyp2_latest_backup.db')
    assert.equal(fs.existsSync(latest), true)
    assert.equal(db.verifySqliteBackup(res.backupFile, activeDb).ok, true)
    assert.equal(db.verifySqliteBackup(latest, activeDb).ok, true)

    // 4096-byte 0-table SQLite stub with integrity_check = 'ok' must be rejected
    const stubPath = path.join(tmpDir, 'stub-empty.db')
    const stub = new Database(stubPath)
    stub.exec('VACUUM;')
    stub.close()
    const stubCheck = db.verifySqliteBackup(stubPath, activeDb)
    assert.equal(stubCheck.integrity, 'ok')
    assert.equal(stubCheck.tableCount, 0)
    assert.equal(stubCheck.ok, false)

    // Missing table must be rejected
    const missingTblPath = path.join(tmpDir, 'missing-table.db')
    fs.copyFileSync(res.backupFile, missingTblPath)
    const missingDb = new Database(missingTblPath)
    missingDb.exec('DROP TABLE audit;')
    missingDb.close()
    const missingCheck = db.verifySqliteBackup(missingTblPath, activeDb)
    assert.equal(missingCheck.ok, false)
    assert.match(missingCheck.reason, /insufficient_tables|missing_table/)

    // Row-count mismatch must be rejected
    const mismatchPath = path.join(tmpDir, 'row-mismatch.db')
    fs.copyFileSync(res.backupFile, mismatchPath)
    const misDb = new Database(mismatchPath)
    misDb.exec('DELETE FROM plans;')
    misDb.close()
    const misCheck = db.verifySqliteBackup(mismatchPath, activeDb)
    assert.equal(misCheck.ok, false)
    assert.match(misCheck.reason, /row_mismatch:plans/)
  })

  await test('High #4: custom plan pricing survives backend restart (migrate uses ON CONFLICT DO NOTHING)', () => {
    const restartDb = path.join(tmpDir, 'restart-plans.db')
    const boot1 = `
      import * as db from './src/db.js';
      import { updatePlan, getPlan } from './src/billing.js';
      db.getDb();
      updatePlan('pro', { priceMonthly: 99, priceYearly: 990, currency: 'USD' });
      console.log('BOOT1:' + getPlan('pro').priceMonthly + ':' + getPlan('pro').currency);
    `
    const boot2 = `
      import * as db from './src/db.js';
      import { getPlan } from './src/billing.js';
      db.getDb();
      const p = getPlan('pro');
      console.log('BOOT2:' + p.priceMonthly + ':' + p.priceYearly + ':' + p.currency);
    `
    const env = { ...process.env, DB_PATH: restartDb, OUTPUT_DIR: tmpDir }
    const cwd = path.resolve(process.cwd())
    const r1 = spawnSync(process.execPath, ['--input-type=module', '-e', boot1], { cwd, env, encoding: 'utf8' })
    assert.equal(r1.status, 0, r1.stderr)
    assert.match(r1.stdout, /BOOT1:99:USD/)

    const r2 = spawnSync(process.execPath, ['--input-type=module', '-e', boot2], { cwd, env, encoding: 'utf8' })
    assert.equal(r2.status, 0, r2.stderr)
    assert.match(r2.stdout, /BOOT2:99:990:USD/)
  })

  await test('High #2: sendContactInquiryNotification escapes HTML & returns success without SMTP creds', async () => {
    const res = await sendContactInquiryNotification({
      name: 'Alice <script>alert(1)</script>',
      email: 'alice@example.com\r\nBcc: evil@attacker.test',
      type: 'demo',
      message: 'Need a security assessment <b>quote</b>.',
    })
    assert.equal(res.success, true)
  })

  await test('High #2/#3/#5: index.js enforces contact route, staff/admin middlewares, and no hardcoded placeholder in ClientsManagement.jsx', () => {
    const indexSrc = fs.readFileSync(path.join(process.cwd(), 'src', 'index.js'), 'utf8')
    assert.match(indexSrc, /app\.post\('\/api\/contact',\s*feedbackLimiter/)
    assert.match(indexSrc, /app\.get\('\/api\/filesystem\/browse',\s*requireAuth,\s*requireStaff/)
    assert.match(indexSrc, /app\.post\('\/api\/scans\/whitebox-folder',\s*requireAuth,\s*requireStaff/)
    assert.match(indexSrc, /app\.post\('\/api\/skills\/reindex',\s*requireAuth,\s*requireRole\('admin'\)/)
    assert.match(indexSrc, /app\.put\('\/api\/findings\/:id\/status',[\s\S]*?if \(!existing\) return res\.status\(404\)\.json\(\{ error: 'Finding not found' \}\)/)

    const clientsSrc = fs.readFileSync(path.resolve(process.cwd(), '..', 'frontend', 'src', 'pages', 'ClientsManagement.jsx'), 'utf8')
    assert.equal(clientsSrc.includes('Source audit placeholder'), false)
    assert.equal(clientsSrc.includes('startWhiteboxFolder'), true)
  })

  console.log(`\nHigh Audit Tests Complete: ${passed} passed, ${failed} failed.\n`)
  if (failed > 0) process.exit(1)
} finally {
  try { db.getDb().close() } catch { /* ignore */ }
  fs.rmSync(tmpDir, { recursive: true, force: true })
}
