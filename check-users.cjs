const Database = require('better-sqlite3');
const db = new Database('../output/fyp2.db', { readonly: true });
const users = db.prepare('SELECT id, username, email, role, password_hash FROM users').all();
console.log(JSON.stringify(users.map(u => ({ id: u.id, username: u.username, email: u.email, role: u.role, hash: (u.password_hash||'').slice(0,15) })), null, 2));
db.close();