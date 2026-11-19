const OSV_URL = 'https://api.osv.dev/v1/query'

export async function queryOsv({ ecosystem = 'npm', name, version } = {}) {
  const packageName = String(name || '').trim()
  const packageVersion = String(version || '').trim()
  if (!packageName || !packageVersion || packageName.length > 200 || packageVersion.length > 100) {
    return { error: 'name and version are required' }
  }
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), 12000)
  try {
    const response = await fetch(OSV_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'user-agent': 'SentinelAI/2.0' },
      body: JSON.stringify({ package: { ecosystem, name: packageName }, version: packageVersion }),
      signal: controller.signal,
    })
    if (!response.ok) return { error: `OSV HTTP ${response.status}` }
    const data = await response.json()
    return {
      ecosystem,
      name: packageName,
      version: packageVersion,
      vulnerabilities: (data.vulns || []).map(vuln => ({
        id: vuln.id,
        summary: vuln.summary || '',
        aliases: vuln.aliases || [],
        published: vuln.published || null,
        modified: vuln.modified || null,
        references: (vuln.references || []).slice(0, 10).map(ref => ref.url).filter(Boolean),
        affected: vuln.affected || [],
      })),
    }
  } catch (error) {
    return { error: error.name === 'AbortError' ? 'OSV request timed out' : error.message }
  } finally {
    clearTimeout(timeout)
  }
}

export default { queryOsv }
