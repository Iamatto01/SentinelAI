# Security Review — SentinelAI (FYP2PROJECT)

**Date:** 2026-09-30  
**Reviewer:** Senior QA Engineer (Copilot)  
**Scope:** Full repository audit — backend (Express + SQLite + Socket.IO), frontend (React + Vite), agents, pipelines, billing, auth, email, database migrations.

---

## Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 2 |
| 🟠 HIGH | 2 |
| 🟡 MEDIUM | 6 |
| ⚪ LOW | 3 |
| **Total** | **13** |

All **CRITICAL** and **HIGH** issues have been **fixed and runtime-verified**. All **MEDIUM** issues have been **fixed and runtime-verified**. **LOW** issues are documented for future improvement.

---

## Findings Table

| # | Severity | File | Lines | Vulnerability | Confidence |
|---|----------|------|-------|---------------|------------|
| 1 | 🔴 CRITICAL | `backend/src/index.js` | ~359 | Duplicated SQL INSERT string + duplicate `role:` property in `POST /api/auth/register` caused `SyntaxError` preventing server boot | 10/10 |
| 2 | 🔴 CRITICAL | `backend/src/pipeline.js` | `runBlackbox`/`retryFailedBlackbox` writes; reads in preview log, `runNativeTool`, `chainInjectionTests`, `extractFindingsFromOutput` | Singleton `UnifiedPipeline` stored per-scan target in shared mutable `this._currentTarget` while 6+ unqueued launchers allow concurrent scans → cross-scan target contamination; one tenant's exploit tooling fires at another tenant's host | 10/10 |
| 3 | 🟠 HIGH | `backend/src/billing.js` + `index.js` | ~99, ~709, ~757, ~776, ~832, ~1302, ~2499 | `COMMUNITY_FREE_ACCESS_MODE` defaulted to `true` (fail-open) + substring-based authorization (`includes()` both directions) exposed all clients' projects, scans, findings, dashboard totals to any authenticated client | 10/10 |
| 4 | 🟠 HIGH | `backend/src/index.js` | ~2442 | Stripe webhook trusted unverified request body when `STRIPE_WEBHOOK_SECRET` unset (it is unset), allowing unauthenticated subscription fulfilment | 10/10 |
| 5 | 🟡 MEDIUM | `backend/src/index.js` + `email.js` | ~904, templates | Unauthenticated, unrate-limited `/api/feedback` with unescaped `category`/`message` interpolated into email HTML/subject → HTML/header injection and mailbox flooding | 10/10 |
| 6 | 🟡 MEDIUM | `backend/src/pipeline.js` | `finish()` | Never released `_loginForms` / `_blackboxMeta` (and `_urlPool` only on success) → unbounded per-scan memory growth in 24/7 unattended runs | 10/10 |
| 7 | 🟡 MEDIUM | `backend/src/pipeline.js` | `_ctl()` | Lazily re-created control entries, so `pauseScan`/`resumeScan`/`stopScan` on finished scan resurrected state that `finish()` deleted | 10/10 |
| 8 | 🟡 MEDIUM | `backend/src/pipeline.js` | `_patternScan` IMPACT map | `'A05:2025-Injection'` declared twice; SSRF entry silently overwrote SQLi/command-injection fallback text | 10/10 |
| 9 | 🟡 MEDIUM | `backend/src/db.js` | 56, 450-500 | `migrate()` swallowed all error classes, masking non-duplicate-column failures (disk full, lock contention) so schema drift went unnoticed | 10/10 |
| 10 | 🟡 MEDIUM | `backend/src/billing.js` | 526 | `consumeScanQuota` would `TypeError` on unresolvable subscription because `getUserSubscription` can return `null` | 10/10 |
| 11 | ⚪ LOW | `frontend/` | build output | Main bundle 1,959 kB / Vite >500 kB chunk warning (cosmetic/perf) | 8/10 |
| 12 | ⚪ LOW | `backend/src/db.js` + `index.js` + `Shell.jsx` | 64, register, "Analyst Portal" | Inconsistent `analyst` vs `client` role story across schema default, registration, and UI | 8/10 |
| 13 | ⚪ LOW | `.env` + `index.js` | - | `DEFAULT_ADMIN_PASSWORD=admin` doesn't match stored bcrypt hash; `STRIPE_WEBHOOK_SECRET` now hard deployment prerequisite (webhook 503 without it) | 8/10 |

---

## Fixes Applied

### 1. CRITICAL — Server Boot Blocker (`index.js:359`)
**Fixed:** Removed duplicated SQL INSERT string and duplicate `role:` property in `POST /api/auth/register`. Handler now runs a single parameterised `INSERT` with `role = 'client'`.

### 2. CRITICAL — Cross-Scan Target Contamination (`pipeline.js`)
**Fixed:** Eliminated shared mutable `this._currentTarget`. Refactored to explicit `target` parameter threaded through all 6 read sites (`previewNativeCommand`, `runNativeTool`, `chainInjectionTests`, `extractFindingsFromOutput` via `processToolOutput`) and all 3 callers (`runBlackbox` batch map, `retryFailedBlackbox` retry loop, `chainInjectionTests` call). Removed abandoned `AsyncLocalStorage` approach. Added `_beginScan()` to clear tombstones for in-place re-runs, `_markFinished()` + `FINISHED_TOMBSTONE_MAX` for control-state hardening, and `releaseScanState()` to clean all 5 per-scan maps.

### 3. HIGH — Fail-Open Data Scoping (`billing.js:99` + `index.js`)
**Fixed:** `COMMUNITY_FREE_ACCESS_MODE` now fail-closed (`=== 'true'`). Replaced all fuzzy substring authorization with strict `canAccessProject(user, project)` using exact ID/email/username matching. Verified: client sees 0 projects/scans/findings; admin sees all (72 scans, 148 findings).

### 4. HIGH — Unsigned Stripe Webhook (`index.js:2442`)
**Fixed:** `POST /api/billing/webhook` now fails closed: **503** when `STRIPE_WEBHOOK_SECRET` unset (it is unset), **400** on missing signature/rawBody or signature mismatch. Verified: forged payloads return 503, no subscription upgrade occurs.

### 5. MEDIUM — Feedback Injection & Flooding (`index.js:904` + `email.js`)
**Fixed:** Added `feedbackLimiter` (10/hour), `FEEDBACK_CATEGORIES` allowlist (matches frontend's 5 values), `FEEDBACK_MAX_LENGTH = 5000`, integer `rating` clamp 1–5. Added module-scope `escapeHtml()` and escaped all user-controlled interpolations in 4 email templates; CRLF-stripped subjects. Verified: empty→400, >5000→413, 8th call→429, XSS payload→sanitised 200.

### 6. MEDIUM — Pipeline Map Leaks (`pipeline.js:finish()`)
**Fixed:** New `releaseScanState(scanId)` deletes all 5 per-scan maps (`control`, `_lastProgressEmit`, `_urlPool`, `_loginForms`, `_blackboxMeta`). `finish()` now calls `releaseScanState()` + `_markFinished()`. Verified by `qa_leak.cjs` harness: before fix leaked `_loginForms` + `_blackboxMeta`; after fix **no leak detected**.

### 7. MEDIUM — Control-State Resurrection (`pipeline.js:_ctl()`)
**Fixed:** `_ctl(scanId, { create = false })` non-creating by default; refuses to create for tombstoned scans. `pauseScan`/`resumeScan`/`stopScan` use `{ create: true }` and no-op on `undefined`. `isPaused`/`isStopped` use optional chaining. Verified: `stopScan()` on finished scan no longer resurrects control entry.

### 8. MEDIUM — Duplicate IMPACT Key (`pipeline.js:_patternScan`)
**Fixed:** Merged two `'A05:2025-Injection'` entries; restored accidentally deleted `'A02:2025-Security Misconfiguration'`. Map now has exactly one entry per OWASP key.

### 9. MEDIUM — Silent Migration Failures (`db.js`)
**Fixed:** Replaced 30 bare `catch { /* already exists */ }` with `catch (e) { if (!/duplicate column name/i.test(String(e))) throw e }` for all `ADD COLUMN` migrations (`findings`, `scans`, `github_repos`, `consultation_requests`, `projects.cover`, `idx_gh_repos_name`). Only 2 intentional bare catches remain (best-effort backup cleanup).

### 10. MEDIUM — Null Subscription TypeError (`billing.js:526`)
**Fixed:** `consumeScanQuota` now guards `if (!sub) throw new Error('Unable to resolve an active subscription...')` before quota logic. Verified all 4 branches: fresh user→auto trial OK, expired→throws, inactive+exhausted→throws, unknown user→clean error (no TypeError).

---

## Verification Evidence

| Check | Result |
|-------|--------|
| `node --check` all 34 backend `.js` files | ✅ 0 failures |
| `npx vite build` (frontend) | ✅ exit 0, 14.86s |
| Backend boot (`node src/index.js`) | ✅ `[FYP2] Unified Pentest Platform backend listening on http://localhost:5000` |
| `GET /api/health` | ✅ 200 |
| Client data scoping (`qa_probe_2`) | ✅ `/api/projects` `[]`, `/api/scans` `[]`, `/api/dashboard` totals 0 |
| Admin data scoping (minted JWT) | ✅ `/api/scans` 72, `/api/dashboard` 148 findings |
| Feedback validation | ✅ 400/413/429/sanitised 200 |
| Stripe webhook fail-closed | ✅ 503 without secret, 503 with bogus signature |
| `consumeScanQuota` branches | ✅ all 4 paths return clean results |
| Pipeline leak test (`qa_leak.cjs`) | ✅ no leak, no resurrection |
| `_beginScan` tombstone clear | ✅ re-run not blocked |

---

## Open Items / Configuration Notes

1. **`STRIPE_WEBHOOK_SECRET`** — Must be set in production `.env` or webhook will return 503. This is now a hard deployment prerequisite.
2. **`DEFAULT_ADMIN_PASSWORD=admin`** — Does not match stored bcrypt hash; admin HTTP login fails. Workaround: mint JWT directly (as done in testing).
3. **Role inconsistency** — Schema default `'analyst'` (`db.js:64`), registration writes `'client'`, UI shows "Analyst Portal". Decision needed: unify to `'client'` or `'analyst'`.
4. **Frontend bundle size** — 1,959 kB main chunk; consider code-splitting for production performance.

---

## Methodology

1. **Mechanical verification** — `node --check` every backend file, `vite build` frontend.
2. **Runtime boot & smoke tests** — Live server, register/login, authenticated API probes.
3. **Targeted manual review** — Auth/RBAC, DB migrations, billing/Stripe, pipeline/orchestrator, email, frontend runtime.
4. **Fix → re-verify loop** — Each fix validated at runtime before proceeding.
5. **Cleanup** — Removed all test users, scratch files, temp scripts; stopped background server.

---

*All fixes are committed to the working tree (uncommitted). Ready for final commit and PR.*