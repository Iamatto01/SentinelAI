const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const db = new Database('../output/fyp2.db', { readonly: true });
const u = db.prepare('SELECT * FROM users WHERE username = ?').get('admin');
const candidates = ['kali', 'admin', 'password', 'admin123', 'Kali', 'sentinel'];
for (const c of candidates) {
  try {
    const ok = bcrypt.compareSync(c, u.password_hash);
    console.log(`${c} => ${ok}`);
  } catch (e) { console.log(`${c} => ERR ${e.message}`); }
}
db.close();