import Database from 'better-sqlite3';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { existsSync } from 'fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const outputDir = join(__dirname, '..', '..', 'output');

const dbs = ['fyp2.db', 'fyp2_backup_manual.db', 'fyp2_latest_backup.db'];
for (const name of dbs) {
  const dbPath = join(outputDir, name);
  if (!existsSync(dbPath)) { console.log(`\n=== ${name}: NOT FOUND ===`); continue; }
  console.log(`\n=== ${name} ===`);
  const db = new Database(dbPath);
  
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
  console.log('TABLES:', tables.map(t => t.name).join(', '));
  
  if (!tables.some(t => t.name === 'scans')) { db.close(); continue; }
  
  const scans = db.prepare('SELECT id, target, target_type, mode, status, created_at FROM scans ORDER BY created_at DESC').all();
  console.log(`SCANS: ${scans.length}`);
  for (const s of scans) {
    console.log(`  ${s.id.slice(-8)} ${s.mode} ${s.target_type} ${s.status} ${s.created_at?.slice(0,19)} target=${s.target?.slice(0,60)}`);
  }
  
  const findings = db.prepare("SELECT id, scan_id, title, severity, evidence FROM findings WHERE title LIKE '%eval%'").all();
  console.log(`EVAL FINDINGS: ${findings.length}`);
  for (const f of findings) {
    try {
      const ev = JSON.parse(f.evidence || '{}');
      console.log(`  [${f.severity}] ${f.title} | file: ${ev.file} line: ${ev.line}`);
    } catch { console.log(`  [${f.severity}] ${f.title}`); }
  }
  
  db.close();
}