# SentinelAI

AI-powered SIEM & Vulnerability Assessment platform with 24/7 continuous monitoring.

## What's inside

- `frontend/` — React client (Vite + Tailwind)
- `backend/` — Express backend (API, Socket.IO, AI Worker, Scanner)
- `vulnerable-target/` — Intentionally vulnerable test app for scanning

## Quick Start (Development)

```bash
npm run dev
```

This single command starts **both** frontend and backend using `concurrently`.

- **Open:** http://localhost:5173 (this is the only URL you need)
- Backend runs at `:5000` behind the scenes (Vite proxies API calls automatically)

## Default Logins

| Role | Username | Password |
|------|----------|----------|
| Admin | admin | admin |
| Analyst | analyst | analyst |
| Client | client | client |

## Testing with Vulnerable Target

```bash
cd vulnerable-target
npm start
```

This starts a deliberately vulnerable app at `http://localhost:3001`.
You can scan it from the SentinelAI dashboard.

## Environment Variables

Copy `.env.example` to `.env` and configure:

- `GROQ_API_KEY` — Required for AI features (get from groq.com)
- `TURSO_DATABASE_URL` — Cloud database (optional, uses local SQLite if not set)
- `TURSO_AUTH_TOKEN` — Cloud database auth token

## Architecture

```
Browser (localhost:5173)
  └── Vite Dev Server (proxy /api/* to backend)
        └── Express Backend (localhost:5000)
              ├── Scanner Modules (nmap, nikto, api probes, etc.)
              ├── AI Worker (Groq/Llama for analysis)
              ├── Monitor Scheduler (24/7 SIEM)
              ├── Log Analyzer (Splunk-like AI log analysis)
              └── Database (Turso cloud or local SQLite)
```