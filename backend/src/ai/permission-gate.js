import { URL } from 'node:url'

function isIpPrivate(hostname) {
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) return false
  const [a, b] = hostname.split('.').map(Number)
  if (a === 10) return true
  if (a === 127) return true
  if (a === 0) return true
  if (a === 169 && b === 254) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  return false
}

function isLocalHost(hostname) {
  const h = String(hostname || '').toLowerCase()
  return h === 'localhost' || h.endsWith('.localhost') || h === '::1'
}

function targetAllowedByRegex(targetUrl) {
  const allowedRegex = process.env.AI_ALLOWED_TARGET_REGEX || ''
  const blockedRegex = process.env.AI_BLOCKED_TARGET_REGEX || ''

  if (blockedRegex) {
    try {
      const re = new RegExp(blockedRegex, 'i')
      if (re.test(targetUrl)) return { ok: false, reason: 'Target blocked by policy regex' }
    } catch (_) {
      // Ignore invalid regex configuration to avoid breaking all scans.
    }
  }

  if (allowedRegex) {
    try {
      const re = new RegExp(allowedRegex, 'i')
      if (!re.test(targetUrl)) return { ok: false, reason: 'Target does not match allow-list regex' }
    } catch (_) {
      // Ignore invalid regex configuration to avoid breaking all scans.
    }
  }

  return { ok: true }
}

export function canRunAIAction({ user, action, target, project }) {
  if (!user) return { allowed: false, reason: 'Authentication required' }

  if (!['admin', 'analyst'].includes(user.role)) {
    return { allowed: false, reason: `Role ${user.role} cannot run AI action ${action}` }
  }

  const allowPrivateTargets = String(process.env.AI_ALLOW_PRIVATE_TARGETS || 'false').toLowerCase() === 'true'

  if (target) {
    let parsed
    try {
      parsed = new URL(target)
    } catch {
      return { allowed: false, reason: 'Invalid target URL' }
    }

    if (!allowPrivateTargets && (isLocalHost(parsed.hostname) || isIpPrivate(parsed.hostname))) {
      return { allowed: false, reason: 'Private or local targets are blocked by AI policy' }
    }

    const regexCheck = targetAllowedByRegex(target)
    if (!regexCheck.ok) return { allowed: false, reason: regexCheck.reason }
  }

  if (project?.status && String(project.status).toLowerCase() === 'archived') {
    return { allowed: false, reason: 'Project is archived' }
  }

  return { allowed: true }
}
