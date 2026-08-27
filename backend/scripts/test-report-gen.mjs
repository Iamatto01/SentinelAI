import { generateReport } from '../src/report.js'
import { all } from '../src/db.js'

async function main() {
  const scans = all(\SELECT id, target, mode, status FROM scans ORDER BY started_at DESC LIMIT 1\)
  if (!scans.length) {
    console.log('No scans found in database')
    return
  }
  const scan = scans[0]
  console.log(\Generating report for latest scan: \ (\)\)
  const res = await generateReport(scan.id, 'info', 'all')
  console.log('Report generation successful:')
  console.log(res)
}

main().catch(console.error)
