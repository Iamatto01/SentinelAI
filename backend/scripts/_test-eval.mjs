// Quick test: reproduce the exact pattern scanner logic on both auth.js files
import { readFileSync } from 'fs';

const feWebPath = 'F:/INI KALI LA/GITHUBB/MyCES_FMS2/FE_Web/src/stores/auth.js';
const feMobilePath = 'F:/INI KALI LA/GITHUBB/MyCES_FMS2/FE_Mobile/src/stores/auth.js';

const RULES = [
  { re: /\beval\s*\(/, sev: 'medium', cwe: 'CWE-95', title: 'eval() usage — possible code injection', ext: () => true },
];

function scanFile(label, filePath) {
  const content = readFileSync(filePath, 'utf8');
  const lines = content.split('\n');
  const findings = [];
  const seen = new Set();
  
  console.log(`\n=== ${label} ===`);
  console.log(`File size: ${content.length} bytes, ${lines.length} lines`);
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line || line.trim().startsWith('//') && !/[:=]/.test(line)) continue;
    for (const r of RULES) {
      if (!r.re.test(line)) continue;
      if (r.ext && !r.ext({ path: filePath })) continue;
      const key = `${filePath}:${r.title}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({ line: i + 1, code: line.trim().slice(0, 200) });
      break;
    }
  }
  
  console.log(`Findings: ${findings.length}`);
  for (const f of findings) {
    console.log(`  Line ${f.line}: ${f.code}`);
  }
  return findings;
}

const feWebFindings = scanFile('FE_Web auth.js', feWebPath);
const feMobileFindings = scanFile('FE_Mobile auth.js', feMobilePath);

console.log('\n=== SUMMARY ===');
console.log(`FE_Web: ${feWebFindings.length} eval findings`);
console.log(`FE_Mobile: ${feMobileFindings.length} eval findings`);

// Now test what happens if the file path uses backslashes (Windows)
console.log('\n=== BACKSLASH TEST ===');
const backslashPath = 'FE_Web\\src\\stores\\auth.js';
const content = readFileSync(feWebPath, 'utf8');
const lines = content.split('\n');
for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  if (/\beval\s*\(/.test(line)) {
    console.log(`Match on line ${i + 1}: ${line.trim().slice(0, 200)}`);
  }
}