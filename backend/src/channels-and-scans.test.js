import assert from 'node:assert/strict'
import * as db from './db.js'

// 1. Test splitMessage edge cases (strings without whitespace)
function splitMessage(str, maxLen = 1900) {
  if (!str) return []
  if (str.length <= maxLen) return [str]
  const chunks = []
  let rem = str
  while (rem.length > maxLen) {
    let splitIdx = rem.lastIndexOf('\n', maxLen)
    if (splitIdx < maxLen * 0.4) splitIdx = rem.lastIndexOf(' ', maxLen)
    if (splitIdx < maxLen * 0.4) splitIdx = maxLen
    chunks.push(rem.slice(0, splitIdx))
    rem = rem.slice(splitIdx).trimStart()
  }
  if (rem.length) chunks.push(rem)
  return chunks
}

// Ensure no chunk exceeds the max limit even with 0 whitespace
const longContinuousStr = 'A'.repeat(5000)
const chunks = splitMessage(longContinuousStr, 1900)
assert.equal(chunks.length, 3)
assert.ok(chunks.every(c => c.length <= 1900))
assert.equal(chunks.join(''), longContinuousStr)

// Test normal whitespace chunking
const sentenceStr = ('Hello world from SentinelAI autonomous pentest engine. '.repeat(50))
const sentenceChunks = splitMessage(sentenceStr, 500)
assert.ok(sentenceChunks.length > 1)
assert.ok(sentenceChunks.every(c => c.length <= 500))

// 2. Test Channel Gateway finding ownership isolation
const testClientId1 = 'test_client_ch1'
const testClientId2 = 'test_client_ch2'
const testScanId1 = 'scan_ch_test1'
const testScanId2 = 'scan_ch_test2'

db.run("DELETE FROM scans WHERE id IN (?, ?)", testScanId1, testScanId2)
db.run("DELETE FROM findings WHERE scan_id IN (?, ?)", testScanId1, testScanId2)

db.run(
  `INSERT INTO scans (id, user_id, client, target, status, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
  testScanId1, testClientId1, 'client1', 'https://target1.example.com', 'completed', new Date().toISOString()
)
db.run(
  `INSERT INTO scans (id, user_id, client, target, status, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
  testScanId2, testClientId2, 'client2', 'https://target2.example.com', 'completed', new Date().toISOString()
)
db.run(
  `INSERT INTO findings (id, scan_id, title, severity, created_at) VALUES (?, ?, ?, ?, ?)`,
  'finding_ch1', testScanId1, 'SQL Injection Target 1', 'critical', new Date().toISOString()
)
db.run(
  `INSERT INTO findings (id, scan_id, title, severity, created_at) VALUES (?, ?, ?, ?, ?)`,
  'finding_ch2', testScanId2, 'RCE Target 2', 'critical', new Date().toISOString()
)

// Client 1 querying their own scan finds it
const ownFindings = db.all(
  `SELECT f.*, s.target FROM findings f JOIN scans s ON f.scan_id = s.id WHERE f.scan_id = ? AND (s.user_id = ? OR s.client = ?)`,
  testScanId1, testClientId1, 'client1'
)
assert.equal(ownFindings.length, 1)
assert.equal(ownFindings[0].title, 'SQL Injection Target 1')

// Client 1 querying Client 2's scan (IDOR attempt) returns empty array
const foreignFindings = db.all(
  `SELECT f.*, s.target FROM findings f JOIN scans s ON f.scan_id = s.id WHERE f.scan_id = ? AND (s.user_id = ? OR s.client = ?)`,
  testScanId2, testClientId1, 'client1'
)
assert.equal(foreignFindings.length, 0)

// Clean up test data
db.run("DELETE FROM findings WHERE scan_id IN (?, ?)", testScanId1, testScanId2)
db.run("DELETE FROM scans WHERE id IN (?, ?)", testScanId1, testScanId2)

console.log('channels and scans security tests: all pass')
