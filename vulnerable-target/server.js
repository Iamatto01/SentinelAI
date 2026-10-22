import express from 'express'
import Database from 'better-sqlite3'
import path from 'node:path'
import fs from 'node:fs'
import { exec } from 'node:child_process'
import http from 'node:http'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'
import multer from 'multer'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()
const PORT = process.env.PORT || 8080

// Setup SQLite in-memory database
const db = new Database(':memory:')

// Uploads directory
const uploadsDir = path.join(__dirname, 'uploads')
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true })
}

// In-memory solved flags set
const solvedFlags = new Set()

const FLAGS = {
  sqli_auth: 'FLAG{sqli_bypass_admin_auth_91a}',
  sqli_union: 'FLAG{sqli_union_credit_cards_4f2}',
  rce_ping: 'FLAG{rce_root_system_shell_7c8}',
  rce_eval: 'FLAG{eval_code_injection_master_52d}',
  lfi_secret: 'FLAG{lfi_company_secret_unlocked_3b1}',
  lfi_passwd: 'FLAG{lfi_system_shadow_passwd_9d0}',
  idor_order: 'FLAG{idor_order_super_secret_55e}',
  ssrf_probe: 'FLAG{ssrf_internal_network_probe_81f}',
  stored_xss: 'FLAG{stored_xss_payload_detonated_23a}',
  file_upload: 'FLAG{unrestricted_web_shell_uploaded_67d}',
  jwt_forge: 'FLAG{jwt_algorithm_none_forged_18c}'
}

// Initialize vulnerable database schema & seed data
db.exec(`
  CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT,
    role TEXT,
    credit_card TEXT,
    email TEXT,
    secret_token TEXT
  );

  CREATE TABLE products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    price REAL,
    description TEXT,
    category TEXT
  );

  CREATE TABLE orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    item TEXT,
    total REAL,
    shipping_address TEXT,
    flag TEXT
  );

  CREATE TABLE feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author TEXT,
    comment TEXT,
    created_at TEXT
  );

  CREATE TABLE secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    secret_value TEXT
  );

  -- Seed users (Passwd MD5 & plaintext for testing)
  INSERT INTO users (username, password, role, credit_card, email, secret_token) VALUES
    ('admin', '21232f297a57a5a743894a0e4a801fc3', 'admin', '4532-1234-8901-9921', 'admin@vulncorp.com', 'tok_super_admin_sec_${FLAGS.sqli_auth}'),
    ('alice', '5f4dcc3b5aa765d61d8327deb882cf99', 'analyst', '4111-2222-3333-4444', 'alice@example.com', 'tok_alice_user_3391'),
    ('bob', 'password123', 'user', '4916-9999-8888-7777', 'bob@example.com', 'tok_bob_client_4812');

  -- Seed products
  INSERT INTO products (name, price, description, category) VALUES
    ('Quantum Secure Laptop', 1299.99, 'Next-gen encrypted hardware workstation', 'Hardware'),
    ('Neural Network Firewall Appliance', 849.50, 'Edge threat detection hardware box', 'Network'),
    ('Zero-Trust Gateway License', 299.00, 'Enterprise annual subscription token', 'Software'),
    ('Tactical Rubber Ducky USB', 45.00, 'Automated keyboard payload injector', 'Tools'),
    ('Hardware Security Module (HSM)', 1999.00, 'Cryptographic key storage vault', 'Hardware');

  -- Seed orders (for IDOR)
  INSERT INTO orders (user_id, item, total, shipping_address, flag) VALUES
    (1, 'Top Secret Quantum Server', 15400.00, 'Executive Floor 42, Suite A, Silicon Valley', '${FLAGS.idor_order}'),
    (2, 'Quantum Secure Laptop', 1299.99, '124 Maple Street, Springfield', 'N/A'),
    (3, 'Tactical Rubber Ducky USB', 45.00, '742 Evergreen Terrace, Springfield', 'N/A');

  -- Seed feedback (for Stored XSS)
  INSERT INTO feedback (author, comment, created_at) VALUES
    ('SecurityAuditor', 'Great portal interface, but please ensure input sanitization is strictly enforced!', '2026-10-20 10:15:00'),
    ('John Doe', 'Fast delivery on the hardware dongles.', '2026-10-21 14:30:00');

  -- Seed secrets (for SQLi Union dump)
  INSERT INTO secrets (title, secret_value) VALUES
    ('Vault Flag', '${FLAGS.sqli_union}'),
    ('Root SSH Key Backup', 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8vK...'),
    ('Master DB Passphrase', 'Sentinel_Master_Root_2026_Uncrackable!');
`)

// Multer storage: Intentionally unrestricted file upload (accepts any extension: .php, .js, .sh, .html)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir)
  },
  filename: (req, file, cb) => {
    // Preserve original filename without sanitization (allowing shell.php, ../ traversal, etc.)
    cb(null, file.originalname)
  }
})
const upload = multer({ storage })

// Middleware
app.use(express.urlencoded({ extended: true }))
app.use(express.json())

// Intentional: Leaky server header & missing security headers (A05: Security Misconfiguration)
app.use((req, res, next) => {
  res.setHeader('X-Powered-By', 'Express/4.21.2 (Node.js v18.0.0-vuln)')
  res.setHeader('Server', 'Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1d')
  // Permissive CORS to allow exploitation from cross-origin
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*')
  res.setHeader('Access-Control-Allow-Credentials', 'true')
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization')
  if (req.method === 'OPTIONS') return res.sendStatus(200)
  next()
})

// Serve uploaded files statically
app.use('/uploads', express.static(uploadsDir))

// Serve static frontend files
app.use(express.static(path.join(__dirname, 'public')))

// ─────────────────────────────────────────────────────────────────────────────
// CTF FLAG SYSTEM API
// ─────────────────────────────────────────────────────────────────────────────
const CHALLENGES = [
  { id: 'rce_ping', name: 'Command Injection (RCE)', category: 'Remote Code Execution', cwe: 'CWE-78', points: 100, flag: FLAGS.rce_ping, hint: 'Execute shell commands via the diagnostic ping tool.' },
  { id: 'sqli_auth', name: 'SQL Injection: Auth Bypass', category: 'Injection', cwe: 'CWE-89', points: 100, flag: FLAGS.sqli_auth, hint: "Login with ' OR '1'='1' -- as administrator." },
  { id: 'sqli_union', name: 'SQLi Union Data Exfiltration', category: 'Injection', cwe: 'CWE-89', points: 100, flag: FLAGS.sqli_union, hint: 'Use UNION SELECT on the product search to dump the secrets table.' },
  { id: 'lfi_secret', name: 'Path Traversal (Internal Secret)', category: 'Broken Access Control', cwe: 'CWE-22', points: 80, flag: FLAGS.lfi_secret, hint: 'Traverse into documents/company_secret.txt' },
  { id: 'lfi_passwd', name: 'LFI System /etc/passwd Leak', category: 'Broken Access Control', cwe: 'CWE-22', points: 90, flag: FLAGS.lfi_passwd, hint: 'Use ../../../etc/passwd via the document viewer.' },
  { id: 'idor_order', name: 'IDOR: Order & Credit Card Leak', category: 'Broken Object Level Auth', cwe: 'CWE-639', points: 70, flag: FLAGS.idor_order, hint: 'Access order ID 1 without authentication.' },
  { id: 'ssrf_probe', name: 'Server-Side Request Forgery', category: 'SSRF', cwe: 'CWE-918', points: 90, flag: FLAGS.ssrf_probe, hint: 'Point the proxy to internal services at 127.0.0.1.' },
  { id: 'file_upload', name: 'Unrestricted File Upload', category: 'File Upload Bypass', cwe: 'CWE-434', points: 100, flag: FLAGS.file_upload, hint: 'Upload a web shell or script file to /api/upload.' },
  { id: 'stored_xss', name: 'Stored Cross-Site Scripting', category: 'Cross-Site Scripting', cwe: 'CWE-79', points: 70, flag: FLAGS.stored_xss, hint: 'Post an unescaped HTML/JavaScript comment on the feedback wall.' },
  { id: 'jwt_forge', name: 'Insecure JWT Forgery', category: 'Cryptographic Failure', cwe: 'CWE-345', points: 100, flag: FLAGS.jwt_forge, hint: 'Forge an admin JWT token using algorithm none or weak secret.' }
]

app.get('/api/flags/status', (req, res) => {
  const list = CHALLENGES.map(c => ({
    id: c.id,
    name: c.name,
    category: c.category,
    cwe: c.cwe,
    points: c.points,
    hint: c.hint,
    solved: solvedFlags.has(c.flag)
  }))
  const solvedCount = list.filter(c => c.solved).length
  const totalScore = list.filter(c => c.solved).reduce((sum, c) => sum + c.points, 0)
  res.json({
    challenges: list,
    solvedCount,
    totalChallenges: CHALLENGES.length,
    score: totalScore,
    maxScore: CHALLENGES.reduce((sum, c) => sum + c.points, 0)
  })
})

app.post('/api/flags/submit', (req, res) => {
  const { flag } = req.body || {}
  if (!flag) return res.status(400).json({ success: false, message: 'Flag is required' })
  const cleanFlag = flag.trim()
  const matched = CHALLENGES.find(c => c.flag === cleanFlag)
  if (matched) {
    const isNew = !solvedFlags.has(cleanFlag)
    solvedFlags.add(cleanFlag)
    return res.json({
      success: true,
      message: isNew ? `🎉 Correct! You solved: ${matched.name} (+${matched.points} pts)` : 'Already solved previously!',
      challenge: matched.name,
      points: matched.points
    })
  } else {
    return res.status(400).json({ success: false, message: '❌ Invalid Flag. Keep hacking!' })
  }
})

// ─────────────────────────────────────────────────────────────────────────────
// VULNERABILITY 1: SQL Injection (Authentication Bypass) [A03 / CWE-89]
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {}
  try {
    // VULNERABLE: Direct SQL string concatenation
    const query = `SELECT * FROM users WHERE username = '${username}' AND (password = '${password}' OR password = '${crypto.createHash('md5').update(password || '').digest('hex')}')`
    console.log(`[SQLi Login Query] ${query}`)
    const user = db.prepare(query).get()

    if (user) {
      res.setHeader('Set-Cookie', `auth_user=${user.username}; Path=/; Role=${user.role}`)
      const isPwnedAdmin = user.role === 'admin' && (!password || password.includes("'") || username.includes("'"))
      return res.json({
        success: true,
        message: `Welcome back, ${user.username}!`,
        user: { id: user.id, username: user.username, role: user.role, email: user.email },
        flag: isPwnedAdmin ? FLAGS.sqli_auth : undefined,
        note: isPwnedAdmin ? '🎯 SQLi Authentication Bypass successfully exploited!' : undefined
      })
    } else {
      return res.status(401).json({ success: false, message: 'Invalid username or password' })
    }
  } catch (err) {
    // VULNERABLE: Database error leakage (Error-based SQLi)
    return res.status(500).json({ error: 'Database query error: ' + err.message, query: err.sql })
  }
})

// ─────────────────────────────────────────────────────────────────────────────
// VULNERABILITY 2: SQL Injection (Union / Search Exfiltration) [A03 / CWE-89]
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/products/search', (req, res) => {
  const q = req.query.q || ''
  try {
    // VULNERABLE: String concatenation in SQL query
    const sql = `SELECT id, name, price, description, category FROM products WHERE name LIKE '%${q}%' OR description LIKE '%${q}%'`
    console.log(`[SQLi Product Query] ${sql}`)
    const rows = db.prepare(sql).all()
    res.json(rows)
  } catch (err) {
    res.status(500).json({ error: 'SQL error: ' + err.message, sqlSnippet: q })
  }
})

// ─────────────────────────────────────────────────────────────────────────────
// VULNERABILITY 3: Reflected Cross-Site Scripting (XSS) [A03 / CWE-79]
// ─────────────────────────────────────────────────────────────────────────────
app.get('/search', (req, res) => {
  const query = req.query.q || ''
  const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Search Results — AbuseLab</title>
      <link rel="stylesheet" href="/style.css">
    </head>
    <body>
      <div class="container" style="max-width: 800px; margin-top: 60px;">
        <div class="card">
          <h2>🔍 Catalog Search Results</h2>
          <p style="color: var(--text-muted); margin-top: 8px;">Reflected parameter: <code>q</code></p>
          <div class="search-banner" style="margin: 20px 0; padding: 16px; background: rgba(239, 68, 68, 0.1); border: 1px solid var(--danger); border-radius: 8px;">
            You searched for: <strong>${query}</strong>
          </div>
          <p><a href="/" class="btn-primary">&larr; Return to Lab Matrix</a></p>
        </div>
      </div>
    </body>
    </html>
  `
  res.send(html)
})

// ─────────────────────────────────────────────────────────────────────────────
// VULNERABILITY 4: Stored Cross-Site Scripting (Stored XSS) [A03 / CWE-79]
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/feedback', (req, res) => {
  const list = db.prepare(`SELECT * FROM feedback ORDER BY id DESC`).all()
  res.json(list)
})

app.post('/api/feedback', (req, res) => {
  const { author, comment } = req.body || {}
  if (!comment) return res.status(400).json({ error: 'Comment required' })
  // VULNERABLE: Saved directly without HTML sanitization or filtering
  db.prepare(`INSERT INTO feedback (author, comment, created_at) VALUES (?, ?, ?)`).run(
    author || 'Anonymous',
    comment,
    new Date().toISOString()
  )
  const isXSS = /<[a-z]|javascript:|onerror|onload/i.test(comment)
  res.json({
    success: true,
    message: 'Feedback posted!',
    flag: isXSS ? FLAGS.stored_xss : undefined
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// VULNERABILITY 5: Remote Command Execution (RCE / Command Injection) [A03 / CWE-78]
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/tools/ping', (req, res) => {
  const host = req.query.host || '127.0.0.1'
  // VULNERABLE: Direct string interpolation into system shell execution
  const command = process.platform === 'win32' ? `ping -n 2 ${host}` : `ping -c 2 ${host}`
  console.log(`[RCE Executing] ${command}`)

  exec(command, { timeout: 8000 }, (err, stdout, stderr) => {
    const rawOut = stdout || stderr || (err ? err.message : 'No output')
    const isPwned = /[;&|`$]/.test(host)
    res.json({
      command,
      output: rawOut,
      success: !err,
      flag: isPwned ? FLAGS.rce_ping : undefined
    })
  })
})

// Direct code evaluation endpoint
app.post('/api/tools/eval', (req, res) => {
  const { code } = req.body || {}
  if (!code) return res.status(400).json({ error: 'Code required' })
  try {
    const result = eval(code) // VULNERABLE: Direct JavaScript execution
    res.json({ success: true, result: String(result), flag: FLAGS.rce_eval })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ─────────────────────────────────────────────────────────────────────────────
// VULNERABILITY 6: Path Traversal / Local File Inclusion (LFI) [A01 / CWE-22]
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/documents/view', (req, res) => {
  const filename = req.query.file || 'terms.txt'
  // VULNERABLE: No normalization or validation against "../"
  const filePath = path.join(__dirname, 'documents', filename)
  console.log(`[Path Traversal Access] ${filePath}`)

  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      // In Linux, try root if ../../../etc/passwd was requested
      if (filename.includes('etc/passwd')) {
        try {
          const pass = fs.readFileSync('/etc/passwd', 'utf8')
          return res.type('text/plain').send(pass + `\n\n# CTF Flag: ${FLAGS.lfi_passwd}\n`)
        } catch (_) {}
      }
      return res.status(404).json({ error: 'File not found: ' + err.message, pathAttempted: filePath })
    }
    let output = data
    if (filename.includes('company_secret.txt')) {
      output += `\nFLAG: ${FLAGS.lfi_secret}\n`
    }
    res.type('text/plain').send(output)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// VULNERABILITY 7: Unrestricted File Upload & Web Shell Execution [A04 / CWE-434]
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' })
  const uploadedPath = `/uploads/${req.file.originalname}`
  res.json({
    success: true,
    message: 'File successfully uploaded to server without restrictions!',
    filename: req.file.originalname,
    url: uploadedPath,
    size: req.file.size,
    flag: FLAGS.file_upload,
    tip: `You can execute or access your payload at ${uploadedPath}`
  })
})

app.get('/api/uploads/list', (req, res) => {
  try {
    const files = fs.readdirSync(uploadsDir).map(name => {
      const stat = fs.statSync(path.join(uploadsDir, name))
      return { name, size: stat.size, modified: stat.mtime }
    })
    res.json(files)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ─────────────────────────────────────────────────────────────────────────────
// VULNERABILITY 8: Broken Object Level Authorization (IDOR) [A01 / CWE-639]
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/orders/:id', (req, res) => {
  const order = db.prepare(`SELECT * FROM orders WHERE id = ?`).get(req.params.id)
  if (!order) return res.status(404).json({ error: 'Order not found' })
  res.json(order)
})

app.get('/api/users/:id', (req, res) => {
  const user = db.prepare(`SELECT id, username, role, credit_card, email, secret_token FROM users WHERE id = ?`).get(req.params.id)
  if (!user) return res.status(404).json({ error: 'User not found' })
  res.json(user)
})

// ─────────────────────────────────────────────────────────────────────────────
// VULNERABILITY 9: Server-Side Request Forgery (SSRF) [A10 / CWE-918]
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/proxy-fetch', (req, res) => {
  const targetUrl = req.query.url
  if (!targetUrl) return res.status(400).json({ error: 'url parameter required' })

  try {
    http.get(targetUrl, (proxyRes) => {
      let body = ''
      proxyRes.on('data', chunk => body += chunk)
      proxyRes.on('end', () => {
        const isInternal = /127\.0\.0\.1|localhost|192\.168\.|10\./.test(targetUrl)
        res.setHeader('Content-Type', proxyRes.headers['content-type'] || 'text/plain')
        if (isInternal) {
          res.setHeader('X-SSRF-Flag', FLAGS.ssrf_probe)
        }
        res.send(body + (isInternal ? `\n\n[SSRF DETECTED] Flag: ${FLAGS.ssrf_probe}` : ''))
      })
    }).on('error', (e) => {
      res.status(500).json({ error: 'Proxy request error: ' + e.message })
    })
  } catch (err) {
    res.status(400).json({ error: 'Invalid URL format' })
  }
})

// ─────────────────────────────────────────────────────────────────────────────
// VULNERABILITY 10: Insecure JWT Token Authentication [A07 / CWE-345]
// ─────────────────────────────────────────────────────────────────────────────
const JWT_SECRET = 'secret123' // Weak secret

function base64url(str) {
  return Buffer.from(str).toString('base64url')
}

function parseJwtPayload(token) {
  try {
    const parts = token.split('.')
    if (parts.length < 2) return null
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'))
  } catch (_) {
    return null
  }
}

app.get('/api/jwt/token', (req, res) => {
  const header = { alg: 'HS256', typ: 'JWT' }
  const payload = { user: 'guest_user', role: 'guest', exp: Math.floor(Date.now() / 1000) + 3600 }
  const data = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`
  const signature = crypto.createHmac('sha256', JWT_SECRET).update(data).digest('base64url')
  const token = `${data}.${signature}`
  res.json({ token, payload, tip: "Try forging this token with role: 'admin' using algorithm 'none' or secret 'secret123'!" })
})

app.post('/api/jwt/verify', (req, res) => {
  const token = req.body.token || req.headers.authorization?.replace('Bearer ', '')
  if (!token) return res.status(400).json({ error: 'Token required' })

  const parts = token.split('.')
  if (parts.length < 2) return res.status(400).json({ error: 'Malformed token' })

  let header = {}
  let payload = {}
  try {
    header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'))
    payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'))
  } catch (e) {
    return res.status(400).json({ error: 'Invalid JSON payload' })
  }

  // VULNERABILITY: Accepts alg "none" without verifying signature!
  if (header.alg && header.alg.toLowerCase() === 'none') {
    if (payload.role === 'admin') {
      return res.json({
        success: true,
        message: '👑 Administrator Access Granted via alg:none JWT bypass!',
        flag: FLAGS.jwt_forge
      })
    }
  }

  // Verify HMAC with weak secret
  const data = `${parts[0]}.${parts[1]}`
  const expectedSig = crypto.createHmac('sha256', JWT_SECRET).update(data).digest('base64url')
  if (parts[2] === expectedSig) {
    if (payload.role === 'admin') {
      return res.json({
        success: true,
        message: '👑 Administrator Access Granted via forged HMAC secret!',
        flag: FLAGS.jwt_forge
      })
    }
    return res.json({ success: true, message: `Logged in as ${payload.user} (${payload.role})` })
  }

  return res.status(401).json({ error: 'Signature verification failed' })
})

// ─────────────────────────────────────────────────────────────────────────────
// SENSITIVE INFORMATION DISCLOSURE
// ─────────────────────────────────────────────────────────────────────────────
app.get('/.env', (req, res) => {
  res.type('text/plain').send(`
# AbuseLab Live Production Secrets
NODE_ENV=production
APP_SECRET=super_secret_jwt_key_99410194819
DB_HOST=127.0.0.1
DB_USER=root
DB_PASS=P@ssw0rdAdmin2026!
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_LIVE_KEY=sk_test_dummy_mock_vulnerable_key_123456
FLAG_ENV=FLAG{env_credentials_exposed_secret_99a}
`)
})

app.get('/backup.sql', (req, res) => {
  res.type('text/plain').send(`
-- AbuseLab Database Dump 2026-10-22
INSERT INTO users VALUES (1, 'admin', '21232f297a57a5a743894a0e4a801fc3', 'admin', '4532-1234-8901-9921', 'admin@vulncorp.com');
INSERT INTO users VALUES (2, 'ceo', 'c4ca4238a0b923820dcc509a6f75849b', 'executive', '4916-1111-2222-3333', 'ceo@vulncorp.com');
-- FLAG: FLAG{sql_backup_dump_unmasked_11b}
`)
})

app.get('/actuator/env', (req, res) => {
  res.json({
    activeProfiles: ['production', 'internal'],
    propertySources: [
      { name: 'systemEnvironment', properties: { USER: 'abuselab-svc', PATH: '/usr/local/bin:/usr/bin' } },
      { name: 'applicationConfig', properties: { 'server.port': 8080, 'spring.datasource.password': 'ProdSecret2026' } }
    ]
  })
})

app.get('/robots.txt', (req, res) => {
  res.type('text/plain').send(`
User-agent: *
Disallow: /admin.html
Disallow: /upload.html
Disallow: /documents/company_secret.txt
Disallow: /backup.sql
Disallow: /.env
Disallow: /actuator
Disallow: /uploads/
`)
})

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n=================================================================`)
  console.log(`🔥 AbuseLab Cybersecurity Vulnerability Playground running on: http://0.0.0.0:${PORT}`)
  console.log(`   - Public Domain:     https://abuse.sentinelai.studio`)
  console.log(`   - Matrix & Board:    http://localhost:${PORT}/`)
  console.log(`   - Terminal (RCE):    http://localhost:${PORT}/admin.html`)
  console.log(`   - SQLi Login:        http://localhost:${PORT}/login.html`)
  console.log(`   - LFI Vault:         http://localhost:${PORT}/documents.html`)
  console.log(`   - Web Shell Upload:  http://localhost:${PORT}/upload.html`)
  console.log(`   - SSRF Proxy:        http://localhost:${PORT}/ssrf.html`)
  console.log(`   - IDOR Profiles:     http://localhost:${PORT}/profile.html`)
  console.log(`   - XSS Feedback:      http://localhost:${PORT}/feedback.html`)
  console.log(`=================================================================\n`)
})
