import fs from 'node:fs'
import path from 'node:path'

/**
 * FolderWalker — recursively reads a project folder and returns source files
 * suitable for whitebox static analysis (runWhitebox).
 *
 * Excludes build artifacts, dependencies, secrets, and binary files by default.
 *
 * Usage:
 *   const { files, stats } = walkFolder('/path/to/project', { maxFiles: 60 })
 *   // files: [{ path: 'src/index.js', content: '...' }, ...]
 */

// Directories to NEVER descend into
const IGNORE_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', '.next', '.nuxt', '.svelte-kit',
  'coverage', '.nyc_output', '__pycache__', '.pytest_cache', '.venv', 'venv', 'env',
  '.idea', '.vscode', '.vs', 'target', 'bin', 'obj', 'vendor', 'tmp', 'temp',
  '.cache', '.parcel-cache', '.turbo', '.vercel', 'public/assets', 'static/assets',
  'logs', 'log', 'uploads', 'storage', 'migrations', 'seeders', 'fixtures',
])

// Files to NEVER include (secrets, lockfiles, binaries)
const IGNORE_FILES = new Set([
  '.env', '.env.local', '.env.development', '.env.production', '.env.test', '.env.staging',
  '.gitignore', '.gitattributes', '.dockerignore', 'docker-compose.yml', 'docker-compose.yaml',
  'Dockerfile', 'dockerfile',
  'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'composer.lock', 'Gemfile.lock',
  'Pipfile.lock', 'poetry.lock', 'Cargo.lock', 'go.sum', 'bun.lockb',
  '.DS_Store', 'Thumbs.db', 'desktop.ini',
  'LICENSE', 'LICENCE', 'COPYING', 'NOTICE',
  '.eslintrc', '.eslintrc.json', '.eslintrc.js', '.prettierrc', '.prettierrc.json',
  'tsconfig.json', 'jsconfig.json', 'tailwind.config.js', 'postcss.config.js',
])

// Extensions that are SOURCE CODE (include)
const SOURCE_EXTS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.py', '.rb', '.php', '.go', '.rs', '.java', '.kt', '.scala',
  '.c', '.h', '.cpp', '.cc', '.hpp', '.cs',
  '.vue', '.svelte', '.astro',
  '.sql', '.prisma', '.graphql', '.gql',
  '.sh', '.bash', '.zsh', '.ps1',
])

// Extensions that MIGHT contain config/secrets (include but flag)
const CONFIG_EXTS = new Set([
  '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf', '.config',
  '.xml', '.properties',
])

// Binary extensions (always skip)
const BINARY_EXTS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ico', '.bmp', '.tiff',
  '.mp3', '.mp4', '.wav', '.avi', '.mov', '.mkv', '.webm',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.zip', '.tar', '.gz', '.rar', '.7z', '.bz2',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.dat',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.map', '.min.js', '.min.css',
  '.db', '.sqlite', '.sqlite3',
])

const MAX_FILE_SIZE = 500_000    // 500KB per file — skip huge generated files
export const DEFAULT_MAX_FILES = 10000  // effectively unlimited — capture all source files
const HARD_MAX_FILES = 100_000   // safety ceiling for a single folder scan
export const DEFAULT_MAX_BYTES = 50_000_000 // 50MB default total payload cap
const HARD_MAX_BYTES = 1_000_000_000 // 1GB ceiling — effectively unlimited for source code

/**
 * Recursively walk a folder and collect source files.
 * @param {string} rootDir — absolute path to project root
 * @param {object} opts
 * @param {number} opts.maxFiles — max files to return (default 1000, hard max 3000)
 * @param {number} opts.maxBytes — max total bytes to collect (default 50MB, hard max 100MB)
 * @param {string[]} opts.extraIgnoreDirs — additional directory names to skip
 * @param {string[]} opts.includeExts — additional extensions to treat as source
 * @returns {{ files: Array<{path: string, content: string, size: number}>, stats: object }}
 */
export function walkFolder(rootDir, opts = {}) {
  const maxFiles = Math.min(Number(opts.maxFiles) || DEFAULT_MAX_FILES, HARD_MAX_FILES)
  const maxBytes = Math.min(Number(opts.maxBytes) || DEFAULT_MAX_BYTES, HARD_MAX_BYTES)
  const extraIgnoreDirs = new Set((opts.extraIgnoreDirs || []).map(d => d.toLowerCase()))
  const includeExts = new Set([...SOURCE_EXTS, ...(opts.includeExts || [])])

  if (!fs.existsSync(rootDir)) {
    return { files: [], stats: { error: `directory not found: ${rootDir}` } }
  }

  const files = []
  const stats = { scanned: 0, skippedDir: 0, skippedFile: 0, skippedBinary: 0, skippedSize: 0, skippedSecret: 0 }
  let totalBytes = 0

  function walk(dir) {
    if (files.length >= maxFiles || totalBytes >= maxBytes) return

    let entries
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true })
    } catch {
      return
    }

    // Sort: prioritize src/, lib/, app/, server/ dirs first (more likely to contain vulns)
    const priority = ['src', 'lib', 'app', 'server', 'backend', 'api', 'routes', 'controllers', 'models', 'services', 'utils', 'helpers', 'middleware', 'auth', 'config']
    entries.sort((a, b) => {
      const aPri = priority.includes(a.name.toLowerCase()) ? 0 : 1
      const bPri = priority.includes(b.name.toLowerCase()) ? 0 : 1
      return aPri - bPri
    })

    for (const entry of entries) {
      if (files.length >= maxFiles || totalBytes >= maxBytes) return

      const fullPath = path.join(dir, entry.name)
      const relPath = path.relative(rootDir, fullPath).replace(/\\/g, '/')
      const nameLower = entry.name.toLowerCase()

      if (entry.isDirectory()) {
        // Skip ignored directories
        if (IGNORE_DIRS.has(nameLower) || extraIgnoreDirs.has(nameLower) || nameLower.startsWith('.')) {
          stats.skippedDir++
          continue
        }
        walk(fullPath)
      } else if (entry.isFile()) {
        stats.scanned++

        // Skip ignored files
        if (IGNORE_FILES.has(entry.name) || IGNORE_FILES.has(nameLower)) {
          stats.skippedSecret++
          continue
        }

        // Skip hidden files (except common config)
        if (entry.name.startsWith('.') && !CONFIG_EXTS.has(path.extname(nameLower))) {
          stats.skippedFile++
          continue
        }

        const ext = path.extname(nameLower)

        // Skip binary files
        if (BINARY_EXTS.has(ext)) {
          stats.skippedBinary++
          continue
        }

        // Only include source or config extensions
        if (!includeExts.has(ext) && !CONFIG_EXTS.has(ext)) {
          stats.skippedFile++
          continue
        }

        // Skip minified/bundled files
        if (/\.min\.(js|css)$/.test(nameLower) || /bundle\./.test(nameLower) || /chunk\./.test(nameLower)) {
          stats.skippedFile++
          continue
        }

        try {
          const stat = fs.statSync(fullPath)
          if (stat.size > MAX_FILE_SIZE) {
            stats.skippedSize++
            continue
          }
          if (stat.size === 0) continue

          const content = fs.readFileSync(fullPath, 'utf8')
          // Skip files that look binary (null bytes in first 1KB)
          if (content.slice(0, 1024).includes('\0')) {
            stats.skippedBinary++
            continue
          }

          files.push({ path: relPath, content, size: stat.size })
          totalBytes += stat.size
        } catch (e) {
          console.error(`[folder-walker] Failed to read ${relPath}: ${e.message}`)
          stats.skippedFile++
        }
      }
    }
  }

  walk(rootDir)

  return {
    files,
    stats: {
      ...stats,
      collected: files.length,
      totalBytes,
      truncated: files.length >= maxFiles || totalBytes >= maxBytes,
    },
  }
}

/**
 * Walk multiple project folders and merge (e.g. frontend + backend).
 * @param {Array<{dir: string, prefix?: string}>} projects
 * @param {object} opts — same as walkFolder
 * @returns {{ files: Array, stats: object }}
 */
export function walkProjects(projects, opts = {}) {
  const maxFiles = Math.min(Number(opts.maxFiles) || DEFAULT_MAX_FILES, HARD_MAX_FILES)
  const maxBytes = Math.min(Number(opts.maxBytes) || DEFAULT_MAX_BYTES, HARD_MAX_BYTES)
  // Fair-share budget: divide the file and byte budget evenly across projects
  // instead of letting the first project greedily consume everything. This
  // prevents a large folder (e.g. 1100 files) from starving smaller but
  // equally important folders (e.g. a 822-file frontend).
  const share = Math.max(1, Math.floor(maxFiles / projects.length))
  const byteShare = Math.max(1_000_000, Math.floor(maxBytes / projects.length))

  const allFiles = []
  const allStats = []
  const projectResults = []
  let leftover = maxFiles - share * projects.length
  let byteLeftover = maxBytes - byteShare * projects.length

  // First pass: each project draws its fair share (it may always use its share
  // even if it could consume more, so no single folder is starved).
  for (const p of projects) {
    const projectBytes = byteShare + Math.max(0, Math.floor(byteLeftover / projects.length))
    const { files, stats } = walkFolder(p.dir, {
      ...opts,
      maxFiles: share,
      maxBytes: projectBytes,
    })
    const prefix = p.prefix || path.basename(p.dir)
    const prefixed = files.map(f => ({ ...f, path: `${prefix}/${f.path}` }))
    projectResults.push({ prefix, dir: p.dir, files: prefixed, stats })
    // Folders that used less than their share give their leftover back to the pool.
    leftover += Math.max(0, share - files.length)
    byteLeftover += Math.max(0, projectBytes - stats.totalBytes)
  }

  // Second pass: redistribute leftover to folders that are still truncated.
  // A folder that used less than its share (e.g. FE_Mobile 205) returns its
  // unused budget to the pool, which is then given to folders that were cut
  // off (e.g. Aziz at its share cap). This achieves the true full-file count
  // across all folders instead of leaving capacity on the table.
  for (const r of projectResults) {
    if (leftover <= 0) break
    if (r.stats.truncated) {
      const before = r.files.length
      const { files, stats } = walkFolder(r.dir, {
        ...opts,
        maxFiles: before + leftover,
      })
      // Re-merge: keep the original priority-ordered files, then append any
      // additional files by diff on path.
      const seen = new Set(r.files.map(f => f.path))
      const extra = files
        .map(f => ({ ...f, path: `${r.prefix}/${f.path}` }))
        .filter(f => !seen.has(f.path))
      r.files.push(...extra)
      const added = r.files.length - before
      r.stats = { ...r.stats, collected: r.files.length, truncated: stats.truncated }
      leftover -= Math.min(leftover, added)
    }
  }

  for (const r of projectResults) {
    allFiles.push(...r.files)
    allStats.push({ dir: r.dir, ...r.stats })
  }

  return { files: allFiles, stats: { projects: allStats, collected: allFiles.length } }
}

export default { walkFolder, walkProjects }
