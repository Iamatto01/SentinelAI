# FYP2 — Unified Pentest Platform

A local-first penetration-testing platform that fuses a tool engine, a specialist-agent reasoning layer, and a PoC knowledge base behind a single orchestration pipeline and web UI.

- **Engine:** hexstrike-ai (100+ tools via REST)
- **Reasoning:** 50 specialist AI agent personas
- **Knowledge:** PayloadsAllTheThings (FTS5-indexed PoC retrieval)
- **Stack:** Node.js (Express + Socket.IO + better-sqlite3) · React + Vite + Tailwind

---

## Prerequisites

- **Node.js** 18+
- **Python 3.10+** (for the hexstrike engine)
- The hexstrike-ai server (`hexstrike_server.py`) and Kali tools (nmap, nuclei, etc.) for real scans

## Setup

```bash
# 1. Install dependencies
cd backend  && npm install
cd ../frontend && npm install

# 2. Configure environment (edit values as needed)
#    .env at the project root already contains working keys/paths.
#    Change JWT_SECRET and DEFAULT_ADMIN_PASSWORD before any real use.

# 3. (Optional) Rebuild the PayloadsAllTheThings index
cd backend && npm run index:payloads
```

## Run

```bash
# Terminal 1 — the tool engine (from the hexstrike-ai directory)
python hexstrike_server.py        # listens on http://127.0.0.1:8888

# Terminal 2 — backend
cd backend && npm run dev         # http://localhost:5000

# Terminal 3 — frontend
cd frontend && npm run dev        # http://localhost:5173
```

Open **http://localhost:5173** and sign in with the default credentials (`admin` / `admin` — change immediately).

## Usage

1. Click **New Scan**.
2. **Blackbox** — enter a target URL/host, pick an objective and modules (or leave empty to let the engine auto-orchestrate), and launch. Watch live stdout and findings stream in.
3. **Whitebox** — paste source code, choose a language, and launch; the code-auditor agent maps logic flaws, hardcoded credentials, and OWASP issues.
4. Triage in **Findings**, monitor subsystem health in **Integrations**, and export a PDF report from any completed scan.

## Project layout

See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the full directory map, REST/WebSocket reference, schema, and integration status.

## Notes

- Local-first: all data lives in `output/fyp2.db` (SQLite). No cloud database required.
- Secrets and PII are redacted before any content is sent to the LLM providers.
- Authorized testing only. Ensure you have permission for any target you scan.
