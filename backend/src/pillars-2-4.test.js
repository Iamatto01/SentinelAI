import assert from 'node:assert/strict'
import { generateWafRules } from './virtual-patching.js'
import { createDependencyPatchPlan } from './dependency-patcher.js'
import { encryptGitHubToken, decryptGitHubToken } from './github-secrets.js'
import { assertPublicHttpUrl } from './ssrf-guard.js'

const rules = generateWafRules({
  id: 'finding-1',
  title: 'Potential SQL injection: /api/search',
  module: 'custom-script:SQL Injection Probe',
  evidence: JSON.stringify({ path: '/api/search' }),
})

assert.equal(rules.scope.path, '/api/search')
assert.equal(rules.scope.family, 'sql')
assert.match(rules.cloudflare.expression, /union|select/)
assert.match(rules.modSecurity, /SecRule REQUEST_URI/)
assert.match(rules.nginx, /\/api\/search/)
assert.equal(rules.awsWaf.action, 'BLOCK')

const fallback = generateWafRules({
  title: 'Finding with unsafe evidence',
  evidence: JSON.stringify({ url: 'https://other.example/unsafe?x=1' }),
})
assert.equal(fallback.scope.path, '/unsafe')

const emptyPlan = await createDependencyPatchPlan([
  { path: 'README.md', content: '# project' },
])
assert.equal(emptyPlan.packages.length, 0)
assert.equal(emptyPlan.actions.length, 0)

const lockPlan = await createDependencyPatchPlan([
  { path: 'package.json', content: '{"dependencies":{}}' },
  { path: 'package-lock.json', content: '{"lockfileVersion":3}' },
])
assert.deepEqual(lockPlan.lockfiles, ['package-lock.json'])

const token = 'ghp_test_token'
assert.equal(decryptGitHubToken(encryptGitHubToken(token)), token)
await assert.rejects(() => assertPublicHttpUrl('http://127.0.0.1:5000'), /private|local/i)

console.log('pillars 2-4 module tests: all pass')
