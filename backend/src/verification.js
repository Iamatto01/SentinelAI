import { assertPublicHttpUrl } from './ssrf-guard.js'

export async function verifyFinding({ target, finding, authorizationAcknowledged = false } = {}) {
  if (!authorizationAcknowledged) throw new Error('Written authorization is required before verification')
  const base = String(target || '').trim()
  const baseCheck = await assertPublicHttpUrl(base)
  const evidence = typeof finding?.evidence === 'string'
    ? (() => { try { return JSON.parse(finding.evidence) } catch { return {} } })()
    : (finding?.evidence || {})
  const candidate = evidence.url || evidence.endpoint || evidence.path || '/'
  const url = new URL(String(candidate), baseCheck.url)
  const endpointCheck = await assertPublicHttpUrl(url.href)
  if (url.origin !== baseCheck.url.origin || endpointCheck.addresses.some((address) => !baseCheck.addresses.includes(address))) {
    throw new Error('verification endpoint must remain same-origin and resolve to the original host')
  }
  const response = await fetch(url, {
    method: 'GET',
    redirect: 'manual',
    headers: { 'user-agent': 'SentinelAI-Verification/2.0', accept: 'text/html,application/json,text/plain;q=0.9,*/*;q=0.1' },
    signal: AbortSignal.timeout(15000),
  })
  const body = (await response.text()).slice(0, 200_000)
  const clean = response.status === 403 || response.status === 404 || response.status === 410
  return {
    verifiedAt: new Date().toISOString(),
    url: url.href,
    method: 'GET',
    status: response.status,
    blocked: clean,
    result: clean ? 'mitigated' : 'needs-review',
    evidence: { contentType: response.headers.get('content-type') || '', bodyLength: body.length },
    note: 'Read-only verification; no exploit payload or state-changing request was sent.',
  }
}

export default { verifyFinding }
