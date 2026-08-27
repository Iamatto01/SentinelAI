import Database from 'better-sqlite3'
import bcrypt from 'bcryptjs'
import * as auth from '../src/auth.js'
import * as db from '../src/db.js'

console.log('Testing getUser with auth module:')
const u1 = auth.getUser('admin@sentinelai.com')
console.log('getUser(admin@sentinelai.com):', u1)
const u2 = auth.getUser('admin')
console.log('getUser(admin):', u2)

if (u1) {
  console.log('bcrypt compare kali with u1:', bcrypt.compareSync('kali', u1.password_hash))
  console.log('Password hash in u1:', u1.password_hash)
  const freshHash = bcrypt.hashSync('kali', 10)
  console.log('Fresh hash compare:', bcrypt.compareSync('kali', freshHash))
}
