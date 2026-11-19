import { queryOsv } from './osv.js'

function parseJson(content, label) {
  try { return JSON.parse(String(content || '')) } catch (error) {
    throw new Error(`${label} is not valid JSON: ${error.message}`)
  }
}

function normaliseFiles(files) {
  if (!Array.isArray(files) || files.length > 200) throw new Error('files must be an array of at most 200 files')
  return files.map(file => {
    const path = String(file?.path || '').replace(/\\/g, '/')
    if (!path || path.includes('..') || path.startsWith('/')) throw new Error(`invalid file path: ${path}`)
    return { path, content: String(file?.content || '') }
  })
}

export async function createDependencyPatchPlan(files) {
  const safeFiles = normaliseFiles(files)
  const manifestFile = safeFiles.find(file => file.path === 'package.json' || file.path.endsWith('/package.json'))
  if (!manifestFile) return { ecosystem: 'npm', packages: [], actions: [], message: 'No package.json found' }
  const lockfiles = safeFiles
    .filter(file => /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml)$/.test(file.path))
    .map(file => file.path)

  const manifest = parseJson(manifestFile.content, manifestFile.path)
  const sections = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']
  const packages = []
  for (const section of sections) {
    for (const [name, declared] of Object.entries(manifest[section] || {})) {
      const version = String(declared).replace(/^[~^<>=* ]+/, '')
      if (!version || !/^\d+(?:\.\d+){0,2}/.test(version)) continue
      const osv = await queryOsv({ ecosystem: 'npm', name, version })
      packages.push({ name, section, declared, version, vulnerabilities: osv.vulnerabilities || [], error: osv.error || null })
    }
  }
  const vulnerable = packages.filter(item => item.vulnerabilities.length)
  return {
    ecosystem: 'npm',
    manifestPath: manifestFile.path,
    lockfiles,
    packages,
    vulnerable,
    actions: vulnerable.map(item => ({
      type: 'manifest-upgrade',
      package: item.name,
      from: item.declared,
      command: 'npm audit fix',
      lockfiles,
      lockfileAction: lockfiles.length ? 'regenerate-and-commit' : 'create-with-package-manager',
      reviewRequired: true,
      reason: item.vulnerabilities.map(v => v.id).join(', '),
    })),
    safety: 'No command was executed and no source file was modified. Apply the generated plan in a reviewed branch.',
  }
}

export default { createDependencyPatchPlan }
