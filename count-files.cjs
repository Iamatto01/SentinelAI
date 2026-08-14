const fs = require('fs');
const path = require('path');

const folders = [
  { dir: '/home/kali/FMS/Aziz', prefix: 'Aziz' },
  { dir: '/home/kali/FMS/FE_Mobile', prefix: 'FE_Mobile' },
  { dir: '/home/kali/FMS/FE_Web', prefix: 'FE_Web' },
];

// Count ACTUAL source files with NO cap
function countReal(dir) {
  let n = 0;
  const ignore = new Set(['node_modules','.git','dist','build','out','.next','.nuxt','.svelte-kit','coverage','.venv','venv','env','.idea','.vscode','target','vendor','tmp','temp','.cache','.turbo','.vercel','public/assets','static/assets','logs','log','uploads','migrations','seeders','fixtures']);
  const srcExts = new Set(['.js','.jsx','.ts','.tsx','.mjs','.cjs','.py','.rb','.php','.go','.rs','.java','.kt','.scala','.c','.h','.cpp','.cc','.hpp','.cs','.vue','.svelte','.astro','.sql','.prisma','.graphql','.gql','.sh','.bash','.zsh','.ps1','.json','.yaml','.yml','.toml','.ini','.cfg','.conf','.config','.xml','.properties']);
  function walk(d) {
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) {
        if (!ignore.has(e.name)) walk(p);
      } else if (e.isFile()) {
        if (srcExts.has(path.extname(e.name))) n++;
      }
    }
  }
  walk(dir);
  return n;
}

console.log('=== ACTUAL FILE COUNTS (no cap) ===');
let total = 0;
for (const f of folders) {
  const c = countReal(f.dir);
  total += c;
  console.log(`  ${f.prefix}: ${c} source files`);
}
console.log(`  TOTAL: ${total} source files`);