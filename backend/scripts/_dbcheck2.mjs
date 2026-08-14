import Database from 'better-sqlite3';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { existsSync } from 'fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const outputDir = join(__dirname, '..', '..', 'output');

const dbNames = ['fyp2.db', 'fyp2_backup_manual.db', 'fyp2_latest_backup.db'];

for (const name of dbNames) {
  const dbPath = join(outputDir, name);
  if (!existsSync(dbPath)) { console.log(name + ': NOT FOUND'); continue; }
  console.log('=== ' + name + ' ===');
  const db = new Database(dbPath);
  try {
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
    console.log('tables: ' + tables.map(t => t.name).join(', '));
  } catch(e) { console.log('error: ' + e.message); }
  
  try {
    const scans = db.prepare('SELECT id, target, target_type, mode, status, created_at FROM scans ORDER BY created_at DESC').all();
    console.log('scans: ' + scans.length);
    for (const s of scans) {
      console.log('  ' + s.id.slice(-8) + ' ' + s.mode + '/' + s.target_type + ' ' + s.status + ' ' + (s.created_at||'').slice(0,19) + ' target=' + (s.target||'').slice(0,80));
    }
  } catch(e) { console.log('scans error: ' + e.message); }
  
  try {
    const fCount = db.prepare('SELECT count(*) as c FROM findings').get();
    console.log('total findings: ' + fCount.c);
    const evalF = db.prepare("SELECT id, scan_id, title, severity, evidence FROM findings WHERE title LIKE '%eval%'").all();
    console.log('eval findings: ' + evalF.length);
    for (const f of evalF) {
      try {
        const ev = JSON.parse(f.evidence || '{}');
        console.log('  [' + f.severity + '] ' + f.title + ' file=' + ev.file + ' line=' + ev.line);
      } catch { console.log('  [' + f.severity + '] ' + f.title); }
    }
    // Also check how many findings per scan
    const perScan = db.prepare('SELECT scan_id, count(*) as c FROM findings GROUP BY scan_id').all();
    console.log('findings per scan:');
    for (const ps of perScan) console.log('  ' + ps.scan_id.slice(-8) + ': ' + ps.c);
  } catch(e) { console.log('findings error: ' + e.message); }
  
  db.close();
  console.log('');
}