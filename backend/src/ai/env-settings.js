/**
 * Helpers for safely updating AI settings in .env without clobbering existing
 * secrets with blank values when UI password inputs are omitted/empty.
 */

export function sanitizeEnvValue(val) {
  if (val === undefined || val === null) return ''
  return String(val).replace(/[\r\n\0]/g, '').trim()
}

/**
 * Apply non-empty AI key/model updates to an existing .env text buffer and
 * target env map, preserving existing secrets whenever an input is blank.
 *
 * @param {string} content Existing .env contents
 * @param {Record<string, unknown>} updates Mapping of ENV_KEY -> candidate value
 * @param {Record<string, string | undefined>} [envTarget=process.env]
 * @returns {string} Updated .env contents ending with newline
 */
export function applyAiEnvUpdates(content, updates, envTarget = process.env) {
  let next = String(content || '')
  for (const [key, val] of Object.entries(updates || {})) {
    const safeVal = sanitizeEnvValue(val)
    if (!safeVal) continue
    const regex = new RegExp(`^\\s*${key}\\s*=[^\\r\\n]*`, 'm')
    if (regex.test(next)) {
      next = next.replace(regex, () => `${key}="${safeVal}"`)
    } else {
      const trimmedEnd = next.replace(/[\r\n]+$/, '')
      next = trimmedEnd ? `${trimmedEnd}\n${key}="${safeVal}"` : `${key}="${safeVal}"`
    }
    if (envTarget) envTarget[key] = safeVal
  }
  const normalized = next.trimEnd()
  return normalized ? `${normalized}\n` : ''
}
