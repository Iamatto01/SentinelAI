import { generateReport } from "./src/report.js"
const out = await generateReport("scan_680fd9bf-ac09-4001-b570-a13b07d1f9ed", "info", "all", { reportType: "simple" })
console.log("done", out?.file || out)
