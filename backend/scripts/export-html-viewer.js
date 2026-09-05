import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dbPath = path.resolve(__dirname, '../../output/fyp2.db');
const outHtmlPath = path.resolve(__dirname, '../../output/db-browser.html');

const db = new Database(dbPath, { readonly: true });

const scans = db.prepare('SELECT id, target, mode, status, progress, risk_score, created_at FROM scans ORDER BY created_at DESC').all();
const findings = db.prepare('SELECT id, scan_id, title, severity, cwe_id, cve_id, module, created_at FROM findings ORDER BY rowid DESC').all();
const users = db.prepare('SELECT id, username, email, role, created_at, last_login FROM users').all();
const logs = db.prepare('SELECT id, scan_id, level, message, ts FROM logs ORDER BY id DESC LIMIT 200').all();

const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SentinelAI - Local Database Viewer</title>
  <style>
    :root {
      --bg: #0d1117;
      --card: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-muted: #8b949e;
      --accent: #58a6ff;
      --crit: #f85149;
      --high: #db6d28;
      --med: #d29922;
      --low: #3fb950;
      --info: #58a6ff;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      margin: 0;
      padding: 24px;
    }
    h1 { color: #58a6ff; margin-bottom: 4px; display: flex; align-items: center; gap: 10px; }
    .subtitle { color: var(--text-muted); margin-bottom: 24px; font-size: 14px; }
    .nav { display: flex; gap: 8px; border-bottom: 1px solid var(--border); padding-bottom: 12px; margin-bottom: 20px; }
    .tab-btn {
      background: var(--card);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 8px 16px;
      border-radius: 6px;
      cursor: pointer;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .tab-btn.active {
      background: #1f6feb;
      border-color: #388bfd;
      color: white;
    }
    .badge-count {
      background: rgba(255,255,255,0.2);
      padding: 2px 7px;
      border-radius: 12px;
      font-size: 12px;
    }
    .table-container {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow-x: auto;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 13px;
    }
    th, td {
      padding: 10px 14px;
      border-bottom: 1px solid var(--border);
    }
    th {
      background: #21262d;
      color: #f0f6fc;
      position: sticky;
      top: 0;
    }
    tr:hover { background: rgba(255,255,255,0.03); }
    .sev-critical { background: rgba(248,81,73,0.2); color: var(--crit); border: 1px solid var(--crit); }
    .sev-high { background: rgba(219,109,40,0.2); color: var(--high); border: 1px solid var(--high); }
    .sev-medium { background: rgba(210,153,34,0.2); color: var(--med); border: 1px solid var(--med); }
    .sev-low { background: rgba(63,185,80,0.2); color: var(--low); border: 1px solid var(--low); }
    .sev-info { background: rgba(88,166,255,0.2); color: var(--info); border: 1px solid var(--info); }
    .tag {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
    }
    .search-box {
      width: 100%;
      max-width: 400px;
      padding: 8px 12px;
      margin-bottom: 14px;
      background: #0d1117;
      border: 1px solid var(--border);
      border-radius: 6px;
      color: white;
      outline: none;
    }
    .search-box:focus { border-color: #58a6ff; }
  </style>
</head>
<body>

  <h1>🗄️ SentinelAI Local Database Viewer</h1>
  <div class="subtitle">Database Path: <code>${dbPath}</code> (Total Scans: ${scans.length} | Findings: ${findings.length} | Users: ${users.length})</div>

  <div class="nav">
    <button class="tab-btn active" onclick="switchTab('scans')">🔍 Scans <span class="badge-count">${scans.length}</span></button>
    <button class="tab-btn" onclick="switchTab('findings')">🛡️ Findings <span class="badge-count">${findings.length}</span></button>
    <button class="tab-btn" onclick="switchTab('users')">👤 Users <span class="badge-count">${users.length}</span></button>
    <button class="tab-btn" onclick="switchTab('logs')">📜 Recent Logs <span class="badge-count">${logs.length}</span></button>
  </div>

  <input type="text" id="searchInput" class="search-box" placeholder="Filter rows..." onkeyup="filterTable()">

  <!-- SCANS -->
  <div id="tab-scans" class="tab-content">
    <div class="table-container">
      <table id="table-scans">
        <thead>
          <tr>
            <th>Scan ID</th>
            <th>Target</th>
            <th>Mode</th>
            <th>Status</th>
            <th>Progress</th>
            <th>Created At</th>
          </tr>
        </thead>
        <tbody>
          ${scans.map(s => `
            <tr>
              <td><code>${s.id}</code></td>
              <td><b>${s.target}</b></td>
              <td><span class="tag sev-info">${s.mode}</span></td>
              <td><span class="tag ${s.status === 'completed' ? 'sev-low' : s.status === 'running' ? 'sev-medium' : 'sev-high'}">${s.status}</span></td>
              <td>${s.progress || 0}%</td>
              <td>${s.created_at}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  </div>

  <!-- FINDINGS -->
  <div id="tab-findings" class="tab-content" style="display:none;">
    <div class="table-container">
      <table id="table-findings">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Title</th>
            <th>CWE / CVE</th>
            <th>Module</th>
            <th>Scan ID</th>
            <th>Date</th>
          </tr>
        </thead>
        <tbody>
          ${findings.map(f => `
            <tr>
              <td><span class="tag sev-${(f.severity || 'info').toLowerCase()}">${f.severity || 'info'}</span></td>
              <td><b>${f.title}</b></td>
              <td>${f.cwe_id || ''} ${f.cve_id ? '<span class="tag sev-critical">' + f.cve_id + '</span>' : ''}</td>
              <td><code>${f.module || '-'}</code></td>
              <td><code>${f.scan_id}</code></td>
              <td>${f.created_at}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  </div>

  <!-- USERS -->
  <div id="tab-users" class="tab-content" style="display:none;">
    <div class="table-container">
      <table id="table-users">
        <thead>
          <tr>
            <th>User ID</th>
            <th>Username</th>
            <th>Email</th>
            <th>Role</th>
            <th>Created At</th>
            <th>Last Login</th>
          </tr>
        </thead>
        <tbody>
          ${users.map(u => `
            <tr>
              <td><code>${u.id}</code></td>
              <td><b>${u.username}</b></td>
              <td>${u.email || '-'}</td>
              <td><span class="tag sev-info">${u.role}</span></td>
              <td>${u.created_at}</td>
              <td>${u.last_login || '-'}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  </div>

  <!-- LOGS -->
  <div id="tab-logs" class="tab-content" style="display:none;">
    <div class="table-container">
      <table id="table-logs">
        <thead>
          <tr>
            <th>ID</th>
            <th>Level</th>
            <th>Message</th>
            <th>Timestamp</th>
          </tr>
        </thead>
        <tbody>
          ${logs.map(l => `
            <tr>
              <td>${l.id}</td>
              <td><span class="tag ${l.level === 'error' ? 'sev-critical' : l.level === 'warn' ? 'sev-medium' : 'sev-info'}">${l.level}</span></td>
              <td>${l.message}</td>
              <td>${l.ts}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  </div>

  <script>
    let currentTab = 'scans';
    function switchTab(tabId) {
      currentTab = tabId;
      document.querySelectorAll('.tab-content').forEach(el => el.style.display = 'none');
      document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
      document.getElementById('tab-' + tabId).style.display = 'block';
      event.currentTarget.classList.add('active');
      filterTable();
    }

    function filterTable() {
      const q = document.getElementById('searchInput').value.toLowerCase();
      const rows = document.querySelectorAll('#table-' + currentTab + ' tbody tr');
      rows.forEach(r => {
        const text = r.innerText.toLowerCase();
        r.style.display = text.includes(q) ? '' : 'none';
      });
    }
  </script>
</body>
</html>`;

fs.writeFileSync(outHtmlPath, html, 'utf8');
console.log('Exported database viewer HTML to:', outHtmlPath);

