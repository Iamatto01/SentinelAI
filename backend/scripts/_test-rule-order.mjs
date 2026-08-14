// Test which rules before the eval rule match eval(fn)()
const line = '      eval(fn)();';

const rules = [
  { re: /(?:api[_-]?key|apikey|secret|password|passwd|token|private[_-]?key)\s*[:=]\s*['"][A-Za-z0-9_\-+/=]{16,}['"]/i, title: 'Hardcoded secret' },
  { re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, title: 'Private key' },
  { re: /(?:query|execute|raw|queryRunner|getConnection|createQuery|createQueryBuilder)\s*\(\s*[`'"].*\$[\{(]/, title: 'SQLi' },
  { re: /\.query\s*\(\s*(?!['"][^'"]*['"]\s*,\s*\[)/, title: 'DB query' },
  { re: /mysql_query\s*\(\s*['"][^'"]*\$_(?:GET|POST|REQUEST)/, title: 'PHP SQLi' },
  { re: /(?:select|insert|update|delete)\s+.*\+.*\b(?:req|request|params|query|body|input|param)\b/i, title: 'SQL concat' },
  { re: /\b(?:eval|exec|execSync|execFileSync|spawnSync|child_process\.exec|subprocess\.(?:call|check_output|Popen)|os\.(?:system|popen))\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|input|user|data)/, title: 'Command exec with user input' },
  { re: /\beval\s*\(/, title: 'eval() usage' },
];

console.log('Testing line: "' + line + '"');
console.log('');

for (let i = 0; i < rules.length; i++) {
  const r = rules[i];
  const matches = r.re.test(line);
  console.log((i+1) + '. [' + (matches ? 'MATCH' : '----') + '] ' + r.title);
  if (matches) console.log('   regex: ' + r.re);
}

console.log('');
console.log('=== The FIRST matching rule (# above) wins due to "break" ===');
console.log('The eval rule is at position 8.');
console.log('If any rule 1-7 matches first, eval is never checked.');