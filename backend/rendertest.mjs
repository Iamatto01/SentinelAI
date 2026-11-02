import db from "file:///F:/FYP2PROJECT/backend/src/db.js"
import { generateReport } from "file:///F:/FYP2PROJECT/backend/src/report.js"

const scanId = "scan_680fd9bf-ac09-4001-b570-a13b07d1f9ed"
for (const rt of ["simple", "full"]) {
  const t0 = Date.now()
  try {
    const out = await generateReport(scanId, "info", "all", { reportType: rt })
    console.log(`\n### ${rt.toUpperCase()} rendered in ${Date.now() - t0} ms`)
    console.log(JSON.stringify(out, null, 1))
  } catch (e) {
    console.log(`\n### ${rt.toUpperCase()} FAILED in ${Date.now() - t0} ms`)
    console.log(e.stack?.split("\n").slice(0, 15).join("\n"))
  }
}