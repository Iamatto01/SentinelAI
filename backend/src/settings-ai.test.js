import assert from 'node:assert/strict'
import { applyAiEnvUpdates } from './ai/env-settings.js'

process.env.JWT_SECRET ||= 'test-jwt-secret-settings-ai'

const { LLMClient, maskApiKey } = await import('./ai/llm-client.js')

let passed = 0
let failed = 0

async function test(name, fn) {
  try {
    await fn()
    passed++
    console.log(`  PASS: ${name}`)
  } catch (err) {
    failed++
    console.error(`  FAIL: ${name} -> ${err.message}`)
  }
}

console.log('\n--- Running AI Settings & Key-Preservation Tests ---')

await test('maskApiKey redacts plaintext secrets and handles short/empty values', () => {
  assert.equal(maskApiKey(''), '')
  assert.equal(maskApiKey(null), '')
  assert.equal(maskApiKey('shortkey'), '••••ey')
  const masked = maskApiKey('mock-or-v1-abcdef1234567890wxyz')
  assert.equal(masked, 'mock-o…wxyz')
  assert.equal(masked.includes('abcdef1234567890'), false)
})

await test('checkProvidersHealth omits raw .key and returns hasKey/keyPreview for configured & empty providers', async () => {
  const client = new LLMClient()
  client.openrouter = { key: 'mock-or-secret-abcdef9876', baseUrl: 'http://127.0.0.1:1/v1', model: 'openrouter/free' }
  client.bandelbanget = { key: 'bb-secret-1234567890', keys: ['bb-secret-1234567890'], baseUrl: 'http://127.0.0.1:1/v1', model: 'deepseek-v4-pro' }
  client.groq = { key: '', model: 'openai/gpt-oss-120b' }

  const originalFetch = globalThis.fetch
  globalThis.fetch = async () => new Response(JSON.stringify({ choices: [{ message: { content: 'OK' } }] }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })
  try {
    const providers = await client.checkProvidersHealth()
    assert.equal(providers.length, 3)

    const or = providers.find((p) => p.id === 'openrouter')
    assert.equal('key' in or, false)
    assert.equal(or.hasKey, true)
    assert.equal(or.keyPreview, 'mock-o…9876')

    const bb = providers.find((p) => p.id === 'bandelbanget')
    assert.equal('key' in bb, false)
    assert.equal(bb.hasKey, true)
    assert.equal(bb.keyPreview, 'bb-sec…7890')

    const gr = providers.find((p) => p.id === 'groq')
    assert.equal('key' in gr, false)
    assert.equal(gr.hasKey, false)
    assert.equal(gr.keyPreview, '')
  } finally {
    globalThis.fetch = originalFetch
  }
})

await test('applyAiEnvUpdates preserves existing .env API keys when empty/whitespace/undefined values are submitted', () => {
  const initialEnv = [
    'PORT=5000',
    'GROQ_API_KEY="mock_groq_secret_1111"',
    'GROQ_MODEL="llama-3.1-8b-instant"',
    'OPENROUTER_API_KEY=mock-or-secret_2222',
    'OPENROUTER_MODEL="openrouter/free"',
    'BANDELBANGET_API_KEY="bb_live_secret_3333"',
    'BANDELBANGET_MODEL="deepseek-v4-pro"',
  ].join('\r\n') + '\r\n'

  const envMap = {
    GROQ_API_KEY: 'mock_groq_secret_1111',
    GROQ_MODEL: 'llama-3.1-8b-instant',
    OPENROUTER_API_KEY: 'mock-or-secret_2222',
    BANDELBANGET_API_KEY: 'bb_live_secret_3333',
  }

  const next = applyAiEnvUpdates(initialEnv, {
    GROQ_API_KEY: '',
    GROQ_MODEL: 'llama-3.3-70b-versatile',
    OPENROUTER_API_KEY: '   ',
    OPENROUTER_MODEL: undefined,
    BANDELBANGET_API_KEY: null,
    BANDELBANGET_MODEL: 'deepseek-v4.1',
  }, envMap)

  assert.match(next, /^GROQ_API_KEY="mock_groq_secret_1111"\r?$/m)
  assert.match(next, /^OPENROUTER_API_KEY=mock-or-secret_2222\r?$/m)
  assert.match(next, /^BANDELBANGET_API_KEY="bb_live_secret_3333"\r?$/m)
  assert.match(next, /^GROQ_MODEL="llama-3\.3-70b-versatile"\r?$/m)
  assert.match(next, /^BANDELBANGET_MODEL="deepseek-v4\.1"\r?$/m)
  assert.equal(envMap.GROQ_API_KEY, 'mock_groq_secret_1111')
  assert.equal(envMap.OPENROUTER_API_KEY, 'mock-or-secret_2222')
  assert.equal(envMap.BANDELBANGET_API_KEY, 'bb_live_secret_3333')
  assert.equal(envMap.GROQ_MODEL, 'llama-3.3-70b-versatile')
  assert.equal(envMap.BANDELBANGET_MODEL, 'deepseek-v4.1')
})

await test('applyAiEnvUpdates writes new non-empty keys, appends missing keys, and strips CR/LF/NUL', () => {
  const initialEnv = 'GROQ_API_KEY="mock_groq_old"\n'
  const envMap = { GROQ_API_KEY: 'mock_groq_old' }

  const next = applyAiEnvUpdates(initialEnv, {
    GROQ_API_KEY: '  mock_groq_new_valid  ',
    BANDELBANGET_API_KEY: 'bb_injected\r\nFAKE=1\0',
    OPENROUTER_API_KEY: '',
  }, envMap)

  assert.match(next, /^GROQ_API_KEY="mock_groq_new_valid"$/m)
  assert.match(next, /^BANDELBANGET_API_KEY="bb_injectedFAKE=1"$/m)
  assert.equal(next.includes('OPENROUTER_API_KEY'), false)
  assert.equal(envMap.GROQ_API_KEY, 'mock_groq_new_valid')
  assert.equal(envMap.BANDELBANGET_API_KEY, 'bb_injectedFAKE=1')
})

console.log(`\nSettings AI Tests Complete: ${passed} passed, ${failed} failed.\n`)
if (failed > 0) process.exit(1)
