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

// Legacy MSF_RPC_URL (http://host:port/api/) → host/port/ssl, used as a fallback
// for the newer MSF_RPC_HOST/MSF_RPC_PORT/MSF_RPC_SSL trio.
function parseMsfUrl() {
  const raw = (process.env.MSF_RPC_URL || '').trim()
  if (!raw) return { host: '', port: 0, ssl: false }
  try {
    const u = new URL(raw)
    return {
      host: u.hostname,
      port: u.port ? Number(u.port) : (u.protocol === 'https:' ? 443 : 80),
      ssl: u.protocol === 'https:',
    }
  } catch {
    return { host: '', port: 0, ssl: false }
  }
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
      model: (process.env.OPENROUTER_MODEL || 'openrouter/free').trim(),
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

  outputDir: resolveDir(process.env.OUTPUT_DIR, fs.existsSync('/home/kali/server/database') ? '/home/kali/server/database' : (fs.existsSync('/home/kali/server/SentinelAI_Data') ? '/home/kali/server/SentinelAI_Data' : path.join(PROJECT_ROOT, 'output'))),
  dbPath: resolveDir(process.env.DB_PATH, fs.existsSync('/home/kali/server/database/fyp2.db') ? '/home/kali/server/database/fyp2.db' : (fs.existsSync('/home/kali/server/SentinelAI_Data/fyp2.db') ? '/home/kali/server/SentinelAI_Data/fyp2.db' : path.join(PROJECT_ROOT, 'output', 'fyp2.db'))),

  scan: {
    moduleTimeoutMs: Number(process.env.MODULE_TIMEOUT_MS || 600000),
    maxConcurrency: Number(process.env.MAX_SCAN_CONCURRENCY || 3),
  },

  // Out-of-band (OOB) interaction listener.
  // Real SSRF/XXE/log4j/cmdi/RFI confirmation needs a callback host the target
  // can reach. The embedded listener binds locally; publicBaseUrl tells payload
  // generators which address a remote target should hit (tunnel/LAN IP/reverse
  // proxy). Auto-detected from the LAN interface when unset.
  oob: {
    enabled: (process.env.OOB_ENABLED || 'true').trim() !== 'false',
    bindHost: (process.env.OOB_BIND_HOST || '0.0.0.0').trim(),
    port: Number(process.env.OOB_PORT || 4711),
    // Public base URL as seen by the TARGET (e.g. https://oob.example.com).
    publicBaseUrl: (process.env.OOB_PUBLIC_URL || '').trim(),
    // Optional shared secret so only our tokens are accepted when exposed.
    ttlMs: Number(process.env.OOB_TTL_MS || 900000),
  },

  // Metasploit RPC bridge (msfrpcd). Real MessagePack-RPC client, no msf deps.
  // Accepts both the current MSF_RPC_* names and the legacy MSF_USER/MSF_PASS/
  // MSF_RPC_URL trio so existing deployments keep working after upgrade.
  msf: {
    enabled: (process.env.MSF_ENABLED || 'true').trim() !== 'false',
    host: (process.env.MSF_RPC_HOST || parseMsfUrl().host || '127.0.0.1').trim(),
    port: Number(process.env.MSF_RPC_PORT || parseMsfUrl().port || 55553),
    user: (process.env.MSF_RPC_USER || process.env.MSF_USER || 'msf').trim(),
    password: process.env.MSF_RPC_PASS || process.env.MSF_PASS || '',
    ssl: (process.env.MSF_RPC_SSL || String(parseMsfUrl().ssl)).trim() === 'true',
    // Callback listener handed to exploit modules that need a payload.
    lhost: (process.env.MSF_LHOST || '').trim(),
    lport: Number(process.env.MSF_LPORT || 4444),
    // Auto-run a read-only session survey on new shells.
    autoEnumerate: (process.env.MSF_AUTO_ENUM || 'true').trim() !== 'false',
  },

  // BeEF (Browser Exploitation Framework) hook server. Optional: when unset,
  // browsers-hook steps report "not configured" instead of a dead localhost URL.
  beef: {
    hookUrl: (process.env.BEEF_HOOK_URL || '').trim(),
    user: (process.env.BEEF_USER || 'beef').trim(),
    password: (process.env.BEEF_PASS || '').trim(),
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

  stripe: {
    secretKey: (process.env.STRIPE_SECRET_KEY || '').trim(),
    publishableKey: (process.env.STRIPE_PUBLISHABLE_KEY || '').trim(),
    webhookSecret: (process.env.STRIPE_WEBHOOK_SECRET || '').trim(),
    currency: (process.env.STRIPE_CURRENCY || 'MYR').toLowerCase(),
  },

  duitnow: {
    enabled: true,
    merchantName: process.env.DUITNOW_MERCHANT_NAME || 'MUHAMMAD SAIFUDIN BIN MO',
    merchantAccount: process.env.DUITNOW_ACCOUNT || 'MDN1782300742811690',
    qrPayload: '00020201021126520014A000000615000101068900530220MDN178230074281169025204731153034585802MY5925MUHAMMADSAIFUDINBINMOHDJA6006SEPANG63048577',
    qrImage: '/duitnow-card.png',
  },
}

// Ensure persistent storage and backup directories exist
try {
  fs.mkdirSync(config.outputDir, { recursive: true })
  fs.mkdirSync(path.dirname(config.dbPath), { recursive: true })
  fs.mkdirSync(path.join(config.outputDir, 'backups'), { recursive: true })
  fs.mkdirSync(path.join(config.outputDir, 'reports'), { recursive: true })
} catch (e) {
  // Ignore permission or preexisting directory notices
}

export default config
