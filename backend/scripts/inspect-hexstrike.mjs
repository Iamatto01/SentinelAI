import fs from 'fs'

const text = fs.readFileSync('resources/hexstrike-ai/hexstrike_server.py', 'utf-8')
const lines = text.split('\n')
const routes = []
for (const line of lines) {
  const m = line.match(/@app\.(?:route|post|get)\(['"]([^'"]+)['"]/)
  if (m) routes.push(m[1])
}
console.log('Total routes in hexstrike_server.py:', routes.length)
const toolRoutes = routes.filter(r => r.includes('/api/tools/'))
console.log('Total /api/tools/ routes:', toolRoutes.length)
console.log('Sample tool routes:', toolRoutes.slice(0, 30))
console.log('Intelligence routes:', routes.filter(r => r.includes('/api/intelligence/')))
console.log('Filesystem routes:', routes.filter(r => r.includes('/api/filesystem/')))

