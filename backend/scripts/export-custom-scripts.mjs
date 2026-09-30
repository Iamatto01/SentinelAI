import Database from 'better-sqlite3'
import fs from 'node:fs'
import path from 'node:path'

const db = new Database(path.resolve('..', 'output', 'fyp2.db'), { readonly: true })
const scripts = db.prepare('SELECT * FROM custom_scripts ORDER BY created_at ASC').all()
console.log(`Found ${scripts.length} custom scripts in output/fyp2.db`)

const outDir = path.resolve('src', 'data')
if (!fs.existsSync(outDir)) {
  fs.mkdirSync(outDir, { recursive: true })
}

const outFile = path.join(outDir, 'default-custom-scripts.json')
fs.writeFileSync(outFile, JSON.stringify(scripts, null, 2), 'utf8')
console.log(`Successfully exported ${scripts.length} scripts to ${outFile} (${fs.statSync(outFile).size} bytes)`)
