import path from 'node:path'
import fs from 'node:fs'
import { fileURLToPath } from 'node:url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

// Project root = FYP2PROJECT/
export const PROJECT_ROOT = path.resolve(__dirname, '..', '..')

// Load .env from project root (no dependency) before reading process.env
const envPath = path.join(PROJECT_ROOT, '.env')
if (fs.existsSync(envPath)) {
  for (const line of fs.readFileSync(envPath, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/)
    if (!m) continue
    const key = m[1]
    let val = m[2]
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) val = val.slice(1, -1)
    if (!(key in process.env)) process.env[key] = val
  }
}

function resolveDir(p, fallback) {
  const v = (p || '').trim()
  if (!v) return fallback
  return path.isAbsolute(v) ? v : path.resolve(PROJECT_ROOT, v)
}

export const config = {
  port: Number(process.env.PORT || 5000),
  clientOrigin: process.env.CLIENT_ORIGIN || 'http://localhost:5173,https://sentinelai.studio',
  // Comma-separated whitelist of allowed browser origins (CORS).
  // Includes vite dev ports (5173/5174) and vite preview ports (4173/4174) for local testing.
  corsOrigins: (process.env.CLIENT_ORIGIN || 'http://localhost:5173,http://localhost:5174,http://127.0.0.1:5173,http://127.0.0.1:5174,http://localhost:4173,http://localhost:4174,http://127.0.0.1:4173,http://127.0.0.1:4174,https://sentinelai.studio,http://192.168.68.132:5173,http://192.168.68.132:5174')
    .split(',').map(s => s.trim()).filter(Boolean),

  jwt: {
    secret: process.env.JWT_SECRET || 'dev-secret-change-me',
    issuer: process.env.JWT_ISSUER || 'fyp2-backend',
  },
  defaultAdminPassword: process.env.DEFAULT_ADMIN_PASSWORD || 'kali',
  // Kali sudo password — used for systemctl/apt tool management.
  // Set to empty string for passwordless sudo (NOPASSWD in sudoers is preferred).
  kaliSudoPassword: process.env.KALI_SUDO_PASSWORD || 'kali',

  ai: {
    provider: (process.env.AI_PROVIDER || 'hybrid').trim(),
    openrouter: {
      key: (process.env.OPENROUTER_API_KEY || '').trim(),
      baseUrl: (process.env.OPENROUTER_BASE_URL || 'https://openrouter.ai/api/v1').trim(),
      model: (process.env.OPENROUTER_MODEL || 'deepseek/deepseek-r1-distill-qwen-32b:free').trim(),
    },
    bandelbanget: {
      key: (process.env.BANDELBANGET_API_KEY || '').trim(),
      backupKey: (process.env.BANDELBANGET_BACKUP_API_KEY || '').trim(),
      keys: [
        (process.env.BANDELBANGET_API_KEY || '').trim(),
        (process.env.BANDELBANGET_BACKUP_API_KEY || '').trim(),
      ].filter(Boolean),
      baseUrl: (process.env.BANDELBANGET_BASE_URL || 'https://bandelbanget.xyz/v1').trim(),
      model: (process.env.BANDELBANGET_MODEL || 'deepseek-v4-pro').trim(),
    },
    groq: {
      key: (process.env.GROQ_API_KEY || '').trim(),
      model: (process.env.GROQ_MODEL || 'openai/gpt-oss-120b').trim(),
    },
    scanTimeout: Number(process.env.AI_SCAN_TIMEOUT || 300),
  },

  hexstrike: {
    url: (process.env.HEXSTRIKE_URL || 'http://127.0.0.1:8888').replace(/\/$/, ''),
    enabled: (process.env.HEXSTRIKE_ENABLED || 'true') !== 'false',
    timeoutMs: Number(process.env.HEXSTRIKE_TIMEOUT_MS || 600000),
  },

  // Metasploit RPC configuration (for autonomous exploitation)
  msf: {
    url: (process.env.MSF_RPC_URL || 'http://127.0.0.1:55553/api/').replace(/\/$/, '') + '/',
    username: process.env.MSF_USER || 'msf',
    password: process.env.MSF_PASS || 'msf',
    timeoutMs: Number(process.env.MSF_TIMEOUT_MS || 120000),
  },

  github: {
    // When set, the /api/github/webhook endpoint requires a valid
    // X-Hub-Signature-256 HMAC. When unset, only loopback/LAN requests pass.
    webhookSecret: (process.env.GITHUB_WEBHOOK_SECRET || '').trim(),
  },

  agentsDir: resolveDir(process.env.AGENTS_DIR, path.join(PROJECT_ROOT, 'agents')),

  payloads: {
    dir: resolveDir(process.env.PAYLOADS_DIR, path.join(PROJECT_ROOT, 'knowledge', 'payloads')),
    indexPath: resolveDir(process.env.PAYLOADS_INDEX, path.join(PROJECT_ROOT, 'output', 'payloads-index.json')),
  },

  skills: {
    dir: resolveDir(process.env.SKILLS_DIR, path.join(PROJECT_ROOT, 'knowledge', 'skills')),
  },

  outputDir: path.join(PROJECT_ROOT, 'output'),
  dbPath: path.join(PROJECT_ROOT, 'output', 'fyp2.db'),

  scan: {
    moduleTimeoutMs: Number(process.env.MODULE_TIMEOUT_MS || 600000),
    maxConcurrency: Number(process.env.MAX_SCAN_CONCURRENCY || 3),
  },

  // Channel gateway (OpenClaw-style): Telegram + Discord bots.
  channels: {
    telegram: {
      token: (process.env.TELEGRAM_BOT_TOKEN || '').trim(),
      enabled: Boolean((process.env.TELEGRAM_BOT_TOKEN || '').trim()),
    },
    discord: {
      token: (process.env.DISCORD_BOT_TOKEN || '').trim(),
      enabled: Boolean((process.env.DISCORD_BOT_TOKEN || '').trim()),
    },
  },
}

// Ensure output dir exists
fs.mkdirSync(config.outputDir, { recursive: true })

export default config
