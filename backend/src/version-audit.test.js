import { extractVersions } from './version-audit.js'

let pass = 0
const failures = []

function check(label, got, want) {
  if (Object.is(got, want)) {
    pass++
  } else {
    failures.push({ label, got, want })
  }
}

function findProduct(text, product) {
  return extractVersions(text, 'test').find(item => item.product === product)
}

console.log('\nversion-audit detection')

check(
  'detects Node.js slash version',
  findProduct('Server: Node.js/18.0.0', 'Node.js')?.version,
  '18.0.0',
)

check(
  'detects Node.js v version in parentheses',
  findProduct('Server: vulnerable (Node.js v18.0.0-vuln)', 'Node.js')?.version,
  '18.0.0',
)

check(
  'detects Node version without js suffix',
  findProduct('runtime Node v20.11.1', 'Node.js')?.version,
  '20.11.1',
)

if (failures.length) {
  console.error(JSON.stringify(failures, null, 2))
  process.exitCode = 1
} else {
  console.log(`PASS ${pass}`)
}
