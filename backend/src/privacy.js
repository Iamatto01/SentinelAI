import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'

/** Data privacy: redact secrets/PII before logs broadcast or API processing; wipe sandboxes. */
const PATTERNS = [
  [/sk-or-v1-[a-zA-Z0-9]{40,}/gi, '[REDACTED_OPENROUTER]'],
  [/sk-[a-zA-Z0-9]{40,}/gi, '[REDACTED_API_KEY]'],
  [/gsk_[a-zA-Z0-9]{40,}/gi, '[REDACTED_GROQ]'],
  [/fiq-[a-zA-Z0-9]{20,}/gi, '[REDACTED_AFIQ]'],
  [/ghp_[a-zA-Z0-9]{30,}/gi, '[REDACTED_GITHUB_PAT]'],
  [/Bearer\s+[a-zA-Z0-9._\-]{20,}/gi, 'Bearer [REDACTED]'],
  [/eyJ[a-zA-Z0-9_-]{8,}\.eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_\-]{8,}/g, '[REDACTED_JWT]'],
  [/-----BEGIN[\s\S]*?PRIVATE KEY-----[\s\S]*?-----END[\s\S]*?PRIVATE KEY-----/gi, '[REDACTED_PRIVATE_KEY]'],
  [/(mongodb|postgres|mysql|redis|amqp):\/\/[^:]+:[^@]+@/gi, '$1://[REDACTED]@'],
  [/(api[_-]?key|secret|password|passwd|token|auth)["']?\s*[:=]\s*["']?[a-zA-Z0-9._\-]{8,}["']?/gi, '$1=[REDACTED]'],
  [/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[REDACTED_EMAIL]'],
]

export function redact(text) {
  if (!text || typeof text !== 'string') return text
  let out = text
  for (const [re, rep] of PATTERNS) out = out.replace(re, rep)
  return out
}

export function sanitizeFinding(f) {
  if (!f) return f
  const s = { ...f }
  if (s.description) s.description = redact(s.description)
  if (s.evidence?.data) s.evidence = { ...s.evidence, data: redact(String(s.evidence.data)) }
  if (s.evidence?.raw) s.evidence = { ...s.evidence, raw: redact(String(s.evidence.raw)) }
  return s
}

export async function wipeSandbox(p) {
  if (!p) return false
  const norm = path.resolve(p)
  const tmp = os.tmpdir()
  if (!norm.startsWith(tmp) && !norm.includes('fyp2-sandbox-')) {
    console.warn(`[privacy] refused to wipe non-sandbox path: ${norm}`)
    return false
  }
  try {
    if (fs.existsSync(norm)) { fs.rmSync(norm, { recursive: true, force: true }); return true }
  } catch (e) { console.error(`[privacy] wipe failed: ${e.message}`) }
  return false
}

export default { redact, sanitizeFinding, wipeSandbox }
