/**
 * GitHub Integration & Automated Repo Ingestion Engine
 * Handles GitHub token verification, repository listing, tree & source code fetching,
 * and webhook event parsing for automated continuous security audits.
 */

const GITHUB_API_URL = 'https://api.github.com'

// Common file extensions and directories to ignore during security code audits
const IGNORED_DIRS = [
  'node_modules', '.git', 'dist', 'build', 'out', '.next', '.nuxt',
  'vendor', 'coverage', '.cache', 'public/assets', '__pycache__'
]

const IGNORED_EXTS = [
  '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.mp4', '.mp3',
  '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip', '.tar', '.gz', '.7z',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.min.js', '.min.css', '.map',
  '.lock', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'composer.lock'
]

// Max file size to fetch (150 KB per file) and max total files to process
const MAX_FILE_SIZE = 150 * 1024
const MAX_FILES = 100

export class GitHubClient {
  constructor(token) {
    this.token = token
  }

  async _fetch(endpoint, options = {}) {
    const url = endpoint.startsWith('http') ? endpoint : `${GITHUB_API_URL}${endpoint}`
    const headers = {
      'Accept': 'application/vnd.github.v3+json',
      'User-Agent': 'SentinelAI-Platform',
      ...(this.token ? { 'Authorization': `Bearer ${this.token}` } : {}),
      ...options.headers,
    }

    const res = await fetch(url, { ...options, headers })
    if (!res.ok) {
      let errMsg = `GitHub API Error (${res.status} ${res.statusText})`
      try {
        const data = await res.json()
        if (data.message) errMsg = `GitHub: ${data.message}`
      } catch {}
      const err = new Error(errMsg)
      err.status = res.status
      throw err
    }
    return res.json()
  }

  /**
   * Verify token and get authenticated GitHub profile
   */
  async verifyToken() {
    const user = await this._fetch('/user')
    return {
      id: user.id,
      login: user.login,
      name: user.name || user.login,
      avatar_url: user.avatar_url,
      email: user.email,
      html_url: user.html_url,
      public_repos: user.public_repos,
      total_private_repos: user.total_private_repos || 0,
    }
  }

  /**
   * List repositories for the authenticated user
   */
  async listRepositories(page = 1, perPage = 50) {
    const repos = await this._fetch(`/user/repos?sort=updated&per_page=${perPage}&page=${page}`)
    return repos.map(r => ({
      id: r.id,
      name: r.name,
      full_name: r.full_name,
      owner: r.owner.login,
      html_url: r.html_url,
      description: r.description,
      is_private: r.private,
      default_branch: r.default_branch || 'main',
      language: r.language,
      updated_at: r.updated_at,
      stars: r.stargazers_count,
    }))
  }

  /**
   * Fetch repository tree and retrieve relevant source code files for whitebox analysis
   */
  async fetchRepoSourceFiles(owner, repo, branch = 'main') {
    // 1. Get branch commit SHA
    const branchData = await this._fetch(`/repos/${owner}/${repo}/branches/${branch}`)
    const commitSha = branchData.commit.sha

    // 2. Fetch full tree recursively
    const treeData = await this._fetch(`/repos/${owner}/${repo}/git/trees/${commitSha}?recursive=1`)
    if (!treeData.tree || !Array.isArray(treeData.tree)) {
      throw new Error('Could not retrieve repository file tree from GitHub')
    }

    // 3. Filter relevant source files
    const relevantFiles = treeData.tree.filter(item => {
      if (item.type !== 'blob') return false
      const pathLower = item.path.toLowerCase()

      // Exclude ignored directories
      for (const dir of IGNORED_DIRS) {
        if (pathLower.startsWith(dir + '/') || pathLower.includes('/' + dir + '/')) return false
      }

      // Exclude ignored extensions
      for (const ext of IGNORED_EXTS) {
        if (pathLower.endsWith(ext)) return false
      }

      // Exclude large files
      if (item.size && item.size > MAX_FILE_SIZE) return false

      return true
    }).slice(0, MAX_FILES)

    // 4. Fetch content for selected files in parallel (batches of 8)
    const fileContents = []
    const batchSize = 8

    for (let i = 0; i < relevantFiles.length; i += batchSize) {
      const batch = relevantFiles.slice(i, i + batchSize)
      const results = await Promise.allSettled(
        batch.map(async (file) => {
          const blob = await this._fetch(`/repos/${owner}/${repo}/git/blobs/${file.sha}`)
          let content = ''
          if (blob.encoding === 'base64') {
            content = Buffer.from(blob.content, 'base64').toString('utf-8')
          } else {
            content = blob.content || ''
          }
          return {
            path: file.path,
            size: file.size,
            content,
          }
        })
      )

      for (const res of results) {
        if (res.status === 'fulfilled' && res.value.content) {
          fileContents.push(res.value)
        }
      }
    }

    // 5. Structure into single consolidated source bundle for Whitebox AI Analyzer
    const consolidatedSource = fileContents.map(f => {
      return `// ==========================================\n// FILE: ${f.path}\n// ==========================================\n${f.content}\n`
    }).join('\n\n')

    return {
      owner,
      repo,
      branch,
      commitSha,
      filesCount: fileContents.length,
      fileList: fileContents.map(f => f.path),
      files: fileContents,
      fileContents,
      consolidatedSource,
    }
  }

  /**
   * Post a summary comment or issue to a GitHub Pull Request / Commit
   */
  async postPRComment(owner, repo, prNumber, commentBody) {
    return this._fetch(`/repos/${owner}/${repo}/issues/${prNumber}/comments`, {
      method: 'POST',
      body: JSON.stringify({ body: commentBody }),
    })
  }
}

/**
 * Parses incoming GitHub Webhook event payload
 */
export function parseGitHubWebhook(eventHeader, body) {
  if (eventHeader === 'push') {
    const repoFullName = body.repository?.full_name
    const repoUrl = body.repository?.html_url
    const branch = body.ref ? body.ref.replace('refs/heads/', '') : 'main'
    const commitHash = body.after || body.head_commit?.id || 'HEAD'
    const commitMessage = body.head_commit?.message || 'New commit push'
    const authorEmail = body.head_commit?.author?.email || body.pusher?.email
    const sender = body.sender?.login || 'github-user'

    return {
      type: 'push',
      repoFullName,
      repoUrl,
      branch,
      commitHash,
      commitMessage,
      authorEmail,
      sender,
    }
  }

  if (eventHeader === 'pull_request') {
    const action = body.action // opened, synchronize, reopened
    if (!['opened', 'synchronize', 'reopened'].includes(action)) {
      return null
    }

    const repoFullName = body.repository?.full_name
    const repoUrl = body.repository?.html_url
    const prNumber = body.pull_request?.number
    const branch = body.pull_request?.head?.ref || 'main'
    const commitHash = body.pull_request?.head?.sha
    const prTitle = body.pull_request?.title
    const authorEmail = body.pull_request?.user?.email
    const sender = body.sender?.login

    return {
      type: 'pull_request',
      action,
      repoFullName,
      repoUrl,
      prNumber,
      branch,
      commitHash,
      prTitle,
      authorEmail,
      sender,
    }
  }

  return null
}
