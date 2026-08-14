# FYP2 — Architecture & System State

> **Purpose:** Persistent state file for the Unified Pentest Platform. Read this before any overhaul; update after any structural change.

**Last updated:** 2026-07 — added Monitoring (scheduled rescans), scan pause/resume, finding detail drawer (PoC/CVE/notes), NVD CVE lookup, global AI chat widget, Settings/profile page, project detail modal.

---

## 1. System Overview

FYP2 fuses four source systems into one local-first platform:

| Source | Role in FYP2 |
|---|---|
| **hexstrike-ai** | The tool *engine* — a Flask server exposing 100+ security tools + an intelligent orchestrator via REST. FYP2 delegates ALL tool execution to it. |
| **pentest-ai-agents** | The *reasoning layer* — 50 specialist personas (`agents/*.md`) used to verify findings, route by vuln type, and power code audits. |
| **PayloadsAllTheThings** | The *knowledge base* — PoC markdown staged in `knowledge/payloads/`, indexed by a persistent FTS5 store and retrieved as evidence for findings. |
| **SentinelAI** | *UI/UX inspiration only* — its backend was intentionally **not** reused (user directive). A fresh thin Node orchestration plane replaced it. |

Two assessment modes share **one** `UnifiedPipeline`:

- **Blackbox** — external target → Hexstrike smart-scan / per-tool runs → findings.
- **Whitebox** — pasted source → `code-auditor` agent → findings.

Every finding flows through a 4-stage enrichment chain:
`enrichWithOwasp → payloadsRag.crossReference → aiEngine.verifyFinding → sanitizeFinding → INSERT → emit`.

---

## 2. Directory Structure

```
FYP2PROJECT/
├── .env                      # local config (real API keys; gitignored)
├── ARCHITECTURE.md           # this file
├── README.md                 # setup / run instructions
├── agents/                   # 50 specialist persona .md (pentest-ai-agents)
├── knowledge/
│   └── payloads/             # PayloadsAllTheThings markdown corpus (~201 docs, 47 categories)
├── output/                   # runtime artifacts: fyp2.db, payloads-index, generated PDFs
│   ├── fyp2.db               # SQLite (better-sqlite3, WAL) — app data + FTS5 index
│   └── report-<scanId>.pdf
├── backend/
│   ├── package.json
│   ├── scripts/
│   │   └── index-payloads.js # CLI: build/rebuild RAG index
│   └── src/
│       ├── index.js          # Express + Socket.IO server, all REST routes (entry point)
│       ├── config.js         # env loading (.env), paths, config singleton
│       ├── db.js             # better-sqlite3 connection, migrate(), prepared helpers
│       ├── auth.js           # JWT middleware, signToken, user helpers
│       ├── pipeline.js       # UnifiedPipeline — single orchestration flow (blackbox+whitebox)
│       ├── owasp.js          # OWASP Top-10 mapping + enrichWithOwasp
│       ├── privacy.js        # secret/PII redaction, sandbox wipe
│       ├── report.js         # pdfkit report generator
│       ├── cve.js            # NVD CVE lookup + 24h cve_cache (SQLite)
│       ├── monitor-scheduler.js # scheduled rescans (setTimeout per monitor → real pipeline scans)
│       ├── integrations/
│       │   ├── index.js      # barrel exports (hexstrike, payloadsRag)
│       │   ├── hexstrike.js  # REST client for the engine (runTool, smartScan, etc.)
│       │   └── payloads-rag.js # FTS5 RAG index + retrievePayloads + crossReference
│       └── ai/
│           ├── agent-registry.js # loads persona .md, routes findings → specialist
│           ├── llm-client.js     # hybrid Afiq (reasoning) + Groq (chat) w/ retry
│           └── ai-engine.js      # verifyFinding, auditCode, summarize, chat
└── frontend/
    ├── package.json
    ├── vite.config.js        # dev proxy /api + /socket.io → :5000
    ├── tailwind.config.js
    ├── postcss.config.js
    ├── index.html
    └── src/
        ├── main.jsx
        ├── App.jsx           # routes + Protected wrapper
        ├── index.css         # design system (dark, Tailwind components)
        ├── lib/
        │   ├── api.js        # apiFetch (JWT), endpoint helpers
        │   ├── AuthContext.jsx
        │   └── socket.js     # Socket.IO singleton + subscribeScan
        ├── components/
        │   ├── Shell.jsx     # sidebar layout + New Scan trigger
        │   ├── NewScanModal.jsx # blackbox/whitebox launch form
        │   ├── SeverityBadge.jsx
        │   ├── StatCard.jsx
        │   ├── FindingDetailDrawer.jsx # slide-over: Overview/PoC/CVE/Notes tabs
        │   └── AIChatWidget.jsx # floating global agent chat (all pages)
        └── pages/
            ├── Login.jsx
            ├── Dashboard.jsx
            ├── Scans.jsx
            ├── ScanDetail.jsx   # live terminal + findings + pause/resume/stop
            ├── Findings.jsx     # clickable cards → FindingDetailDrawer
            ├── Projects.jsx     # clickable cards → ProjectDetail modal
            ├── Monitoring.jsx   # scheduled rescans + event feed
            ├── Settings.jsx     # profile, change password, system status
            └── Integrations.jsx
```

---

## 3. Backend — REST API

Base URL `http://localhost:5000`. All routes except `/api/health` and `/api/auth/login` require `Authorization: Bearer <jwt>`.

| Method | Route | Purpose |
|---|---|---|
| GET | `/api/health` | liveness |
| GET | `/api/status` | aggregate: engine, RAG, agents, AI configured |
| POST | `/api/auth/login` | `{username,password}` → `{token,user}` |
| GET | `/api/users/me` | current user |
| PUT | `/api/users/me` | update own email |
| POST | `/api/users/me/password` | change own password (verifies current) |
| GET/POST/DELETE | `/api/projects[/:id]` | project CRUD |
| GET | `/api/scans` | list scans |
| GET | `/api/scans/:id` | scan + findings + recent logs |
| POST | `/api/scans` | **create & run** scan (blackbox `{target,objective,modules,verify}` or whitebox `{files,language,focus,verify}`); returns immediately, runs async |
| POST | `/api/scans/:id/stop` | stop a running scan |
| POST | `/api/scans/:id/pause` | cooperative pause (takes effect at next tool/finding checkpoint) |
| POST | `/api/scans/:id/resume` | resume a paused scan |
| GET/POST | `/api/findings/:id/notes` | per-finding analyst notes |
| GET/POST | `/api/monitors[/:id]` | scheduled-rescan monitor CRUD |
| PUT/DELETE | `/api/monitors/:id` | `{enabled}` toggle / delete |
| GET | `/api/cve/:id` | NVD lookup (24h DB cache; requires internet) |
| GET | `/api/findings` | all findings (+target) |
| PUT | `/api/findings/:id/status` | update triage status |
| GET | `/api/agents` | list personas |
| POST | `/api/agents/chat` | `{message,agent,history}` → reply |
| GET | `/api/payloads/status` | RAG index status |
| POST | `/api/payloads/reindex` | rebuild FTS5 index |
| GET | `/api/payloads/search?q=` | ranked PoC retrieval |
| GET | `/api/engine/status` | hexstrike /health (forced fresh) |
| POST | `/api/engine/analyze` | hexstrike target profiling |
| POST | `/api/engine/attack-chain` | hexstrike attack chain |
| POST | `/api/reports/generate` | `{scanId}` → PDF |
| GET | `/api/reports/download/:scanId` | download PDF |
| GET | `/api/dashboard` | stats for dashboard |

## 4. WebSocket Channels (Socket.IO)

Connections are **JWT-authenticated** (`io.use` middleware) — the client sends the token in the handshake (`socket.js` → `auth:{token}`); unauthenticated sockets are rejected.

Client emits `scan:subscribe <scanId>` to join room `scan:<scanId>`.

| Event | Payload | Emitted when |
|---|---|---|
| `scan:log` | `{scanId, level, message, ts}` | any pipeline log line |
| `scan:update` | `{scanId, progress}` | progress % change |
| `scan:finding` | `{scanId, finding}` | a finding completes the enrichment chain |
| `scan:done` | `{scanId, status, riskScore}` | pipeline finishes |

---

## 5. Database Schema (SQLite — `output/fyp2.db`)

- `users(id, username, email, password_hash, role, created_at, last_login)`
- `projects(id, name, client, description, scope, risk_level, status, created_at, updated_at)`
- `scans(id, project_id, target, target_type, mode, status, template, modules, progress, risk_score, created_at, started_at, finished_at)`
- `findings(id, scan_id, title, description, severity, cvss, cwe_id, owasp_category, module, evidence, poc, remediation, agent_verdict, status, created_at)`
- `logs(id, scan_id, level, message, ts)`
- `payload_index(category, file, title, content, keywords)` — meta mirror of FTS
- `payload_fts` — FTS5 virtual table (category, file, title, content, keywords)
- `audit(id, actor, action, detail, ts)`
- `monitors(id, name, target, target_type, interval_min, modules, enabled, status, last_run, last_status, last_risk, next_run, created_at)`
- `monitor_events(id, monitor_id, scan_id, kind, message, created_at)` — event feed per monitor (info/ok/alert/error)
- `finding_notes(id, finding_id, author, note, ts)`
- `cve_cache(id, data, fetched_at)` — 24h NVD response cache

**Decision:** better-sqlite3 (embedded, local-first) replaces SentinelAI's cloud Turso — no external DB dependency and enables FTS5 for the RAG store.

---

## 6. Integration Status Matrix

| Integration | Module | Status | Notes |
|---|---|---|---|
| Hexstrike engine | `integrations/hexstrike.js` | ✅ wired | REST client; `MODULE_TOOL_MAP` for 20 tools; smart-scan + attack-chain. Engine must be running on `:8888`. |
| Specialist agents | `ai/agent-registry.js` | ✅ active | 50 personas loaded; deterministic keyword routing. |
| LLM (Afiq) | `ai/llm-client.js` | ✅ configured | heavy reasoning: verify + code-audit. |
| LLM (Groq) | `ai/llm-client.js` | ✅ configured | chat + summaries. |
| Payloads RAG | `integrations/payloads-rag.js` | ✅ active | 201 docs indexed; FTS5 bm25 + category fallback; CRLF-safe snippet extraction. |
| OWASP mapping | `owasp.js` | ✅ active | A01–A10 2021 + CWE + keyword heuristics. |
| Privacy/redaction | `privacy.js` | ✅ active | secrets/PII redacted pre-LLM. |
| Monitors (scheduled rescans) | `monitor-scheduler.js` | ✅ active | per-monitor `setTimeout`; each tick runs a real blackbox scan (template `monitor`, maxTools 4). Requires engine on `:8888` for findings. |
| NVD CVE lookup | `cve.js` | ✅ active | NVD API v2 + 24h `cve_cache`; 12s timeout. Requires internet. |
| GitHub OAuth | `.env` (placeholders) | ⬜ not implemented | future whitebox private-repo ingestion. |

---

## 7. Data Flow (Blackbox)

```
User → NewScanModal → POST /api/scans
  → index.js creates scans row, spawns UnifiedPipeline (async)
    → pipeline.runBlackbox
      → hexstrike.smartScan(target)  (or per-tool runTool)
      → for each raw finding: ingestFinding
          enrichWithOwasp → crossReference(RAG) → verifyFinding(agent) → sanitize
          → INSERT findings → io.emit scan:finding
      → finish: compute risk_score → emit scan:done
ScanDetail.jsx subscribes scan:<id> → live terminal + findings render
```

## 8. Data Flow (Whitebox)

```
POST /api/scans {mode:whitebox, files[], language}
  → pipeline.runWhitebox → aiEngine.auditCode (code-auditor agent persona)
  → each reported flaw → same ingestFinding chain → findings
```

---

## 9. Frontend State Dependencies

| Component / Page | Consumes |
|---|---|
| `AuthContext` | `api.me()`, token in localStorage (`fyp2_token`) |
| `Dashboard` | `api.dashboard()` |
| `Scans` | `api.scans()` |
| `ScanDetail` | `api.scan(id)` + WebSocket `scan:*` |
| `Findings` | `api.findings()` + `FindingDetailDrawer` |
| `Projects` | `api.projects()` CRUD + `ProjectDetail` modal (links scans by `project_id`) |
| `Monitoring` | `api.monitors()` CRUD + `api.monitor(id)` events |
| `Settings` | `api.updateMe()`, `api.changePassword()`, `api.status()` |
| `AIChatWidget` | `api.agentChat()` (global, on all Shell pages) |
| `FindingDetailDrawer` | `api.setFindingStatus()`, `api.cve()`, `api.findingNotes()/addFindingNote()` |
| `Integrations` | `api.status()`, `api.agents()`, `api.reindexPayloads()` |
| `NewScanModal` | `api.startScan()` |

Dev proxy: Vite forwards `/api` and `/socket.io` to `localhost:5000`.

---

## 10. Security Hardening (applied)

- **CORS lockdown** — whitelist via `config.corsOrigins` (from `CLIENT_ORIGIN`, comma-separated). Non-whitelisted browser origins are rejected; server-to-server (no Origin) allowed.
- **Login rate-limit** — `express-rate-limit`, 10 attempts / 15 min per IP on `/api/auth/login`.
- **WebSocket auth** — `io.use` JWT verification on every socket handshake.
- **Security headers** — `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`.

## 11. Known Gaps / Next Steps

- GitHub OAuth private-repo ingestion (whitebox) — placeholders in `.env` only.
- Pause/resume is **cooperative**: it takes effect at the next tool run (blackbox module loop) or next finding (whitebox loop); an in-flight hexstrike HTTP call is not aborted mid-request.
- Monitor scans need the hexstrike engine running to produce findings (offline engine → `error` events in the monitor feed).
- Report download assumes same-origin (works through Vite proxy in dev).
- To deploy to `sentinelai.studio`: set `CLIENT_ORIGIN=https://sentinelai.studio`, rotate `JWT_SECRET` + admin password, serve `frontend/dist`, reverse-proxy `/api` + `/socket.io`, keep the engine (`:8888`) firewalled to localhost.
