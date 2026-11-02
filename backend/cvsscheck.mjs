import { CVSS4_TEMPLATES, CVSS4_SEVERITY_BANDS, calculateCvss4, assertTemplateScores, assertClassCeilings, classifyFinding, evaluateFindingCvss } from "./src/cvss4.js"

const t = assertTemplateScores()
const c = assertClassCeilings()
console.log("templates ok:", t.ok, JSON.stringify(t.mismatches))
console.log("ceilings ok :", c.ok, JSON.stringify(c.violations))
console.log("template count:", Object.keys(CVSS4_TEMPLATES).length)

console.log("\n--- family routing on the real scan rows ---")
const rows = [
  ["Possible webshell", "critical", 10, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", "CWE-94"],
  ["Database admin interface exposed", "critical", 5.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", "CWE-798"],
  ["Admin panel discovered: /admin (HTTP 200)", "medium", 5.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", "CWE-798"],
  ["API endpoint discovered", "medium", 0, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", "CWE-200"],
  ["Editor/temp file exposed", "critical", 10, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", "CWE-548"],
  ["Web cache deception possible", "high", 8.7, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", "CWE-524"],
  ["Negative amount accepted", "high", 8.7, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:H".replace("/SA:H","/SA:N"), "CWE-20"],
  ["Potential IDOR/BOLA", "high", 10, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", "CWE-639"],
  ["Missing security header: cross-origin-resource-policy", "low", 10, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", "CWE-1021"],
  ["OS metadata file exposed", "medium", 5.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", "CWE-548"],
  ["No rate limiting on API", "medium", 10, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", "CWE-770"],
  ["Information disclosure page", "high", 8.7, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", "CWE-200"],
  ["WordPress config backup exposed", "critical", 9.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "CWE-548"],
  ["Nginx 1.18 is END-OF-LIFE (undefined) — no security patches for 314 months", "high", 8.7, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", "CWE-1104"],
  ["ELMAH error log exposed", "high", 8.7, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", "CWE-200"],
  ["Git Configuration", "medium", 5.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", "cwe-200"],
  ["Phpinfo page exposed", "high", 8.7, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", "CWE-200"],
  ["Server Header Information Disclosure (nginx/1.18.0)", "info", 0, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N".replace("VC:H","VC:N"), "CWE-200"],
  ["Missing Strict-Transport-Security (HSTS) Header", "high", 2.1, "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N", "CWE-319"],
  ["No HTTP to HTTPS redirect", "medium", 10, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", "CWE-319"],
  ["Session tokens not unique", "critical", 9.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "CWE-331"],
  ["Laravel Ignition debug endpoint exposed", "critical", 10, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", "CWE-489"],
  ["Laravel Telescope exposed", "high", 8.7, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", "CWE-489"],
  ["Next.js dev overlay exposed", "high", 10, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", "CWE-489"],
  ["Web.config exposed with secrets", "critical", 10, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", "CWE-538"],
  ["Exposed config file", "critical", 9.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "CWE-548"],
  ["Dangerous HTTP methods allowed", "info", 10, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", "CWE-650"],
  ["Missing Cookie SameSite Strict", "info", 0, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", "cwe-693"],
  ["Insecure cookie flags — missing Secure, HttpOnly, SameSite", "medium", 5.1, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N", "CWE-614"],
  ["No rate limiting on login form /login — brute-force possible", "info", 10, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", "CWE-307"],
  ["NoSQL injection auth bypass", "critical", 10, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", "CWE-943"],
  ["Clickjacking — no frame protection", "medium", 5.3, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", "CWE-1021"],
  ["Wappalyzer Technology Detection", "info", 0, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", ""],
]
for (const [title, sev, cvss, vec, cwe] of rows) {
  const f = { title, severity: sev, cvss, cvss_vector: vec, cwe_id: cwe }
  const e = evaluateFindingCvss(f)
  const flag = e.reconciled ? "RECON" : "     "
  console.log(`${flag} ${String(sev).padEnd(8)} ${String(cvss).padEnd(5)} -> ${String(e.score).padEnd(5)} ${e.severity.padEnd(9)} ${String(e.findingClass).padEnd(26)} src=${String(e.vectorSource).padEnd(14)} ${e.rejectedVectorReason ? "<<"+e.rejectedVectorReason+">>" : ""} :: ${title.slice(0,60)}`)
}