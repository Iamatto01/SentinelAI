const Database = require('better-sqlite3');
const db = new Database('../output/fyp2.db', { readonly: true });
for (const id of ['scan_d8d71991-4f88-467e-8d21-5abd318aec87', 'scan_071acf77-ec5f-4f0e-8e3f-583ef48fc8dd']) {
  const s = db.prepare('SELECT id, status, progress, token_usage FROM scans WHERE id=?').get(id);
  console.log('=== ' + id.slice(0, 20) + ' ===');
  console.log('status:', s.status, 'progress:', s.progress);
  console.log('token_usage:', s.token_usage);
  console.log('');
}
db.close();