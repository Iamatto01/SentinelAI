# TODO — SentinelAI (FYP2 Project)

## Recently Completed
- [x] Full pipeline (blackbox + whitebox) wired to AI verification with 3-tier fallback
- [x] Auth + RBAC + JWT
- [x] Socket.IO live scan log/finding streaming
- [x] PayloadsAllTheThings RAG (201 docs, FTS5)
- [x] PDF report generation
- [x] All UI pages (Dashboard, Scans, Scan Detail, Findings, Projects, Integrations)
- [x] Payloads pre-indexed on boot
- [x] `ARCHITECTURE.md` + `README.md` documentation
- [x] **Security hardening** — CORS whitelist, login rate-limit (10/15min), WebSocket JWT auth
- [x] **Monitoring page** — scheduled rescans (monitor-scheduler → real pipeline scans) + event feed
- [x] **Scan pause/resume** — cooperative checkpoints in pipeline + UI buttons on ScanDetail
- [x] **Finding detail drawer** — Overview / PoC / CVE / Notes tabs (Findings + ScanDetail)
- [x] **CVE lookup** — NVD API + 24h SQLite cache (`cve.js`, `cve_cache`)
- [x] **Global AI chat widget** — floating agent chat on all pages
- [x] **Settings page** — profile (email), change password, system status
- [x] **Project detail modal** — status/risk, scope, linked scans, delete

## Remaining
- [ ] **Deploy to sentinelai.studio** — production .env + serve frontend + reverse-proxy (below)
- [ ] GitHub OAuth for private-repo whitebox ingestion
- [ ] Multi-user management UI (admin panel)
- [ ] Finding *assignment* (notes done; assignment needs users table wiring)

## Deploy to sentinelai.studio (checklist)
1. Copy `.env` on server; change:
   - `CLIENT_ORIGIN=https://sentinelai.studio`
   - Rotate `JWT_SECRET` (`node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"`)
   - Set a strong `DEFAULT_ADMIN_PASSWORD`
   - Keep `HEXSTRIKE_URL=http://127.0.0.1:8888` (never expose the engine)
2. `cd frontend && npm run build` → serve `dist/` (static).
3. Reverse-proxy (nginx/cloudflared): `sentinelai.studio` → frontend, `/api` + `/socket.io` → `localhost:5000`.
4. Firewall: only 80/443 public; `:5000` and `:8888` localhost-only.
