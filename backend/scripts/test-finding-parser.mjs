import assert from 'node:assert/strict'
import { extractFindingsFromOutput } from '../src/pipeline.js'

const openPort = extractFindingsFromOutput(
  'nmap',
  '22/tcp open ssh OpenSSH 9.2',
).findings[0]
assert.equal(openPort.severity, 'info')

const nmapVulnerability = extractFindingsFromOutput(
  'nmap',
  '| http-vuln-example:\n|   VULNERABLE: remote code execution confirmed',
).findings[0]
assert.equal(nmapVulnerability.severity, 'high')
assert.equal(nmapVulnerability.validationRequired, undefined)

const versionMatch = extractFindingsFromOutput(
  'nmap',
  '| vulners:\n|   CVE-2024-12345 9.8 https://example.test/advisory',
).findings[0]
assert.equal(versionMatch.severity, 'info')
assert.equal(versionMatch.validationRequired, true)

const currentYearCve = extractFindingsFromOutput(
  'nmap',
  `| vulners:\n|   CVE-${new Date().getFullYear()}-12345 9.8 https://example.test/advisory`,
).findings[0]
assert.equal(currentYearCve.severity, 'info')

const katanaPath = extractFindingsFromOutput(
  'katana',
  JSON.stringify({ request: { endpoint: 'https://example.test/admin' } }),
).findings.find((finding) => /path discovered/i.test(finding.title))
assert.equal(katanaPath.severity, 'info')
assert.equal(katanaPath.validationRequired, true)

const discoveredDir = extractFindingsFromOutput(
  'ffuf',
  '[Status: 200, Size: 320, Words: 20, Lines: 4] /backup',
  'https://example.test',
).findings.find((finding) => /backup/i.test(finding.title))
assert.equal(discoveredDir.severity, 'info')
assert.equal(discoveredDir.validationRequired, true)

const blockedSqlmap = extractFindingsFromOutput(
  'sqlmap',
  "[INFO] GET parameter 'id' does not appear to be injectable",
)
assert.equal(blockedSqlmap.findings.length, 0)

const confirmedSqlmap = extractFindingsFromOutput(
  'sqlmap',
  "[INFO] GET parameter 'id' appears to be 'AND boolean-based blind' injectable",
).findings[0]
assert.equal(confirmedSqlmap.severity, 'high')
assert.equal(confirmedSqlmap.validationRequired, undefined)

const unprovenDalfox = extractFindingsFromOutput(
  'dalfox',
  JSON.stringify([{ type: 'reflected', param: 'q', url: 'https://example.test/?q=test' }]),
).findings[0]
assert.equal(unprovenDalfox.severity, 'info')
assert.equal(unprovenDalfox.validationRequired, true)

const nucleiWithoutMatchEvidence = extractFindingsFromOutput(
  'nuclei',
  JSON.stringify({
    'template-id': 'example-check',
    info: { name: 'Example check', severity: 'high' },
  }),
)
assert.equal(nucleiWithoutMatchEvidence.findings.length, 0)

const nucleiWithMatchEvidence = extractFindingsFromOutput(
  'nuclei',
  JSON.stringify({
    'template-id': 'example-check',
    'matched-at': 'https://example.test/path',
    info: { name: 'Example check', severity: 'high' },
  }),
).findings[0]
assert.equal(nucleiWithMatchEvidence.severity, 'high')

console.log('Finding parser tuning tests passed.')
