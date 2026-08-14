import Database from 'better-sqlite3';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const dbPath = join(__dirname, 'fyp2.db');
const db = new Database(dbPath);

const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
console.log('TABLES:', JSON.stringify(tables));

const scans = db.prepare('SELECT id, target, target_type, mode, status, created_at FROM scans ORDER BY created_at DESC').all();
console.log('SCANS:', JSON.stringify(scans, null, 2));

// Check whitebox_meta for any scan
for (const s of scans) {
  const meta = db.prepare('SELECT whitebox_meta FROM scans WHERE id = ?').get(s.id);
  if (meta?.whitebox_meta) {
    console.log(`\n=== Scan ${s.id} whitebox_meta ===`);
    try {
      const parsed = JSON.parse(meta.whitebox_meta);
      console.log(JSON.stringify(parsed, null, 2));
    } catch { console.log(meta.whitebox_meta.slice(0, 500)); }
  }
}

db.close();