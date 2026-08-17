# 🛡️ SentinelAI — Speciality Update

> **FYP2 Unified Pentest Platform — Full System Capability Document**
>
> _A local-first, AI-powered penetration testing platform that fuses a 100+ tool engine, 50 specialist AI agents, and a PoC knowledge base behind a single orchestration pipeline._

---

## Table of Contents

1. [Executive Overview](#1-executive-overview)
2. [AI-Powered Reasoning Engine](#2-ai-powered-reasoning-engine)
3. [Unified Pipeline Architecture](#3-unified-pipeline-architecture)
4. [Autonomous Exploitation Engine](#4-autonomous-exploitation-engine)
5. [Professional PDF Report Generation](#5-professional-pdf-report-generation)
6. [Dual RAG Knowledge Bases (Payloads + 817 Skills)](#6-dual-rag-knowledge-bases)
7. [OWASP 2025 Top 10 Mapping](#7-owasp-2025-top-10-mapping)
8. [Multi-Provider LLM with Fallback](#8-multi-provider-llm-with-fallback)
9. [Real-Time Live Streaming](#9-real-time-live-streaming)
10. [GitHub CI/CD Integration](#10-github-cicd-integration)
11. [Billing & Subscription System](#11-billing--subscription-system)
12. [Security & Privacy Hardening](#12-security--privacy-hardening)
13. [Frontend Feature Showcase](#13-frontend-feature-showcase)
14. [Technology Stack](#14-technology-stack)

---

## 1. Executive Overview

SentinelAI is not just another vulnerability scanner. It is a **complete autonomous penetration testing platform** that combines:

| Layer | Technology | Capability |
|---|---|---|
| **Tool Engine** | Hexstrike-AI (100+ security tools) | Nmap, Nuclei, SQLMap, Dalfox, Katana, Subfinder, HTTPx, WPScan, Nikto, and more — orchestrated via REST |
| **Reasoning Layer** | 50 Specialist AI Agent Personas | Each vulnerability type is routed to a dedicated expert agent (SQLi specialist, XSS specialist, AD attacker, cloud security expert, etc.) |
| **Knowledge Base** | Dual RAG: PayloadsAllTheThings (201 PoC docs) + Cybersecurity Skills (817 practitioner playbooks) | Both FTS5-indexed, retrieved in milliseconds via full-text search |
| **Exploitation Engine** | Autonomous Exploitation Orchestrator (AEO) | Automatically launches exploit campaigns against verified high/critical findings — with risk-gated approval |
| **Report Engine** | PDFKit Professional Reports | Multi-section PDF reports with severity charts, PoC procedures, CVSS breakdowns, and remediation guidance |
| **Platform** | Node.js + Express + Socket.IO + SQLite | Local-first, no cloud DB required, real-time WebSocket streaming |

### What Makes This System WOW

- **50 AI Agents** — Not one generic AI, but 50 specialist personas, each an expert in a specific attack domain
- **Dual RAG Knowledge** — 201 PoC documents + 817 practitioner playbooks, both FTS5-indexed with BM25 ranking
- **AI Self-Correction** — A feedback loop that catches 10 error types in AI output and re-prompts until clean
- **Autonomous Exploitation** — Finds vulnerabilities AND automatically exploits them (with human approval for high-risk actions)
- **Post-Exploitation Engine** — After gaining access: persistence, lateral movement, credential harvesting, data exfiltration
- **Real-Time Everything** — Live terminal output, live findings stream, live exploit progress — all via WebSocket
- **Professional Reports** — PDF reports that rival commercial pentest deliverables
- **GitHub CI/CD** — Automated security scans on every push and pull request
- **Multi-Provider AI** — 4 LLM providers with automatic failover (OpenRouter → Bandelbanget → Groq)
- **Fish Audio Briefing** — Listen to an AI-generated executive summary of your scan results
- **Structural Mapping** — Visual attack surface mapping with finding-to-evidence correlation
- **Billing System** — Tiered subscription plans with Stripe/LemonSqueezy/ToyyibPay payment integration

---

## 2. AI-Powered Reasoning Engine

### 50 Specialist Agent Personas

The system loads **50 specialist pentest AI personas** from `agents/*.md` files, each with deep domain expertise:

```
ad-attacker          api-security         attack-planner       bizlogic-hunter
bug-bounty           c2-operator          cicd-redteam         cloud-security
code-auditor         compliance-mapper    container-breakout   credential-tester
crypto-analyzer      ctf-solver           data-exfiltrator     database-attacker
detection-engineer   engagement-planner   evasion-specialist   exploit-chainer
exploit-guide        forensics-analyst    iot-pentester        lateral-movement
llm-redteam          malware-analyst      mobile-pentester     network-attacker
opsec-anonymizer     osint-collector      password-auditor     payload-crafter
persistence-planner  phishing-operator    poc-validator        privesc-advisor
recon-advisor        report-generator     reverse-engineer     risk-scorer
scada-attacker       social-engineer      stig-analyst         swarm-orchestrator
threat-modeler       traffic-analyzer     vuln-scanner         web-hunter
wireless-pentester
```

### Intelligent Finding Routing

Every finding is **deterministically routed** to the most appropriate specialist agent based on keyword matching against the finding's title, description, CWE, and module. This means:

- SQL injection findings → `database-attacker` agent
- XSS findings → `web-hunter` agent
- Active Directory issues → `ad-attacker` agent
- Cloud misconfigurations → `cloud-security` agent
- LLM/AI vulnerabilities → `llm-redteam` agent

### AI Verification (True/False Positive Detection)

The AI engine doesn't just collect findings — it **verifies** each one:

```
Finding → Specialist Agent Verification → {
  isTruePositive: true/false,
  confidence: 0-100,
  verdict: "reasoning text",
  evidenceTier: 'exploited' | 'validated' | 'observed' | 'needs-validation',
  agent: "which specialist verified it",
  refined: { ... } // AI-refined finding data
}
```

**Precision Mode**: The AI is instructed to "ONLY REPORT CONFIRMED VULNERABILITIES WITH CLEAR EXPLOITATION PATHS" — no hallucinated claims without evidence.

**Heuristic Fallback**: When the LLM is unavailable, a deterministic regex-based `_heuristicVerify()` engine takes over with 12+ true-positive patterns and 4 false-positive patterns, ensuring the system never blindly marks everything as vulnerable.

### AI Code Audit (Whitebox)

The `auditCode()` method performs **multi-pass specialist analysis**:

1. **Pattern Scanner** (deterministic, no AI) — secrets, dangerous functions, insecure config
2. **AI Pass 1: Injection** — SQLi, command injection, XSS, SSTI, deserialization
3. **AI Pass 2: Auth & Secrets** — broken auth, JWT misuse, hardcoded credentials, weak crypto
4. **AI Pass 3: Logic & Config** — IDOR, SSRF, path traversal, CORS, debug endpoints

Each pass uses a **parallel worker pool** (5 concurrent, batch size 3) for speed, with a 120-second safety timeout per pass.

### AI PoC Generation

After verification, the AI generates a **structured Proof of Concept** for each finding:

```json
{
  "pocPayload": "exact payload string",
  "attackCommand": "copy-pasteable curl/python/bash command",
  "exploitSteps": ["step 1", "step 2", "step 3"],
  "impact": "specific business impact",
  "prerequisites": "what access/conditions are needed"
}
```

### Global AI Chat Widget

A floating AI chat widget is available on **every page** — users can ask security questions, request explanations of findings, or get remediation advice from any of the 50 specialist agents at any time.

### AI Feedback Loop — Dynamic Self-Correction

Every AI-generated finding passes through a **self-correcting feedback loop** before being stored:

```
AI Finding → AIFeedbackLoop.selfCorrect()
  → Review for 10 error types:
      generic_poc, missing_steps, missing_command, missing_payload,
      missing_impact, severity_mismatch, hallucinated_path,
      generic_remediation, thin_description, missing_code_evidence
  → If errors found: re-prompt AI with error context (max 2 retries)
  → Corrected finding replaces the original
  → Learned "prompt adjustments" persisted to DB (per-agent)
```

The system **learns from its own mistakes**: recurring error patterns become reusable prompt adjustments that improve future scans — visible in the UI via the AI Feedback Panel (correction rate, review log, learned adjustments).

---

## 3. Unified Pipeline Architecture

### One Pipeline, Two Modes

Both blackbox and whitebox assessments flow through the **same** `UnifiedPipeline`:

```
┌─────────────────────────────────────────────────────────────────────┐
│                     UNIFIED PIPELINE                                │
│                                                                     │
│  BLACKBOX                          WHITEBOX                         │
│  ┌─────────┐                      ┌──────────┐                      │
│  │ Hexstrike│                      │  Source   │                      │
│  │ 100+ tools│                     │  Code     │                      │
│  │ Smart Scan│                     │  Paste    │                      │
│  └────┬────┘                      └────┬─────┘                      │
│       │                                │                             │
│       ▼                                ▼                             │
│  ┌────────────────────────────────────────────┐                     │
│  │          INGEST FINDING (shared)            │                     │
│  │                                            │                     │
│  │  1. OWASP 2025 Enrichment                  │                     │
│  │  2. RAG PoC Cross-Reference                │                     │
│  │  3. Severity Bounds Enforcement            │                     │
│  │  4. AI Verification (specialist agent)     │                     │
│  │  5. Deduplication (fingerprint matching)   │                     │
│  │  6. AI PoC Generation                      │                     │
│  │  7. DB Insert + WebSocket Emit             │                     │
│  │  8. Auto-Exploit (if high/critical)        │                     │
│  └────────────────────────────────────────────┘                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Blackbox Scan Flow

1. **HTTP Baseline Audit** — Security headers, sensitive paths, CORS (always runs, even without engine)
2. **WordPress Detection** — Auto-detects WordPress and conditionally runs WPScan
3. **Hexstrike Smart Scan** — Delegates to the engine for intelligent tool orchestration
4. **Per-Tool Runs** — Individual tool execution (nmap, nuclei, sqlmap, dalfox, katana, etc.)
5. **Subdomain Enumeration** — Discovers and scans subdomains automatically
6. **Native Fallback** — If Hexstrike is offline, switches to native tool execution via `child_process`

### Whitebox Scan Flow

1. **Pattern Scanner** — Fast deterministic scan for secrets, dangerous functions, insecure config
2. **3 AI Audit Passes** — Injection, Auth/Secrets, Logic/Config (parallel worker pool)
3. **File Path Resolution** — Matches truncated AI file paths against the full file list
4. **Severity Bounds** — Caps severity for well-known low-impact categories

### Advanced Pipeline Features

- **Pause / Resume / Stop** — Cooperative checkpoints allow pausing mid-scan
- **Retry Failed** — Re-run only the tools/passes that failed
- **Deduplication** — Fingerprint-based dedup merges repeated detections from multiple sources
- **Severity Bounds Enforcement** — Prevents AI from over-inflating severity (console.log → LOW, missing headers → MEDIUM, RCE → CRITICAL)
- **Risk Score Computation** — Weighted formula: `critical×3 + high×2 + medium×0.8 + low×0.2`
- **Live Progress Tracking** — Throttled (250ms) progress updates via WebSocket

---

## 4. Autonomous Exploitation Engine

### Autonomous Exploitation Orchestrator (AEO)

When a finding is verified as a **true positive** with **confidence ≥ 70%** and severity **high or critical**, the system automatically launches an exploit campaign:

```
Verified Finding → ExploitOrchestrator.launchCampaign()
  → matchExploits() — match finding to exploit techniques
  → classifyRisk() — auto (low) vs gated (medium+)
  → Build ordered attack steps
  → Execute each step:
      - Low risk: auto-execute (enum, PoC, read-only)
      - Medium+ risk: gate for human approval
  → Post-exploitation engine
  → Live WebSocket broadcast
```

### Exploit Technique Registry

The system includes a comprehensive exploit registry mapping vulnerability types to exploitation techniques:

| Vulnerability | Techniques | Post-Exploit |
|---|---|---|
| **SQL Injection** | DB enumeration → Table dump → OS shell | Credential loot, DB dump |
| **XSS** | Payload injection → Cookie theft → Session hijack | Session loot |
| **Command Injection** | Command execution → Reverse shell | Persistence, lateral |
| **File Upload** | Shell upload → Web shell access | Persistence |
| **Path Traversal** | File read → Config extraction | Credential loot |
| **SSRF** | Internal scan → Cloud metadata | Credential loot |
| **JWT Attacks** | Token forge → Auth bypass | Lateral movement |
| **cPanel Auth Bypass (CVE-2026-41940)** | 5-stage detection chain: token leak probe → session validation → forced browsing → privilege check → impact confirmation | Detection-only (no destructive action) |
| **+ many more** | | |

### Post-Exploitation Engine

After a session is established, the post-exploit engine runs:

- **Persistence** — Cron jobs, systemd services, registry keys, SSH authorized_keys
- **Lateral Movement** — Pass-the-hash, PSExec, WMI, SSH key injection
- **Credential Harvesting** — Hash dumps, session tokens, API keys, DB credentials
- **Data Exfiltration** — Staged exfiltration with loot tracking
- **Cleanup** — Artifact removal (optional)

### Metasploit Integration

The system integrates with **Metasploit RPC** for:
- Module execution (exploit/post/auxiliary)
- Session management
- Meterpreter commands
- Post-exploitation modules

### Approval Workflow

Medium+ risk actions require **explicit human approval** before execution:
- The campaign pauses at the approval gate
- The UI shows a pending approval card
- The user can approve or reject each step
- Only after approval does the destructive action execute

---

## 5. Professional PDF Report Generation

### Report Sections

The PDF report generator produces **multi-section professional reports**:

| Section | Content |
|---|---|
| **Cover Page** | Report title, project info, date, risk rating badge |
| **Table of Contents** | Auto-generated section index |
| **1. Executive Summary** | Assessment overview, severity breakdown table with color-coded badges, risk rating |
| **2. Methodology** | Assessment approach, tools used, AI agent passes (whitebox) or tool list (blackbox) |
| **3. Findings Summary** | Severity distribution bar chart, high-priority fix list |
| **4. Detailed Findings** | Per-finding: severity badge, CVSS, CWE, OWASP category, description, evidence, remediation |
| **5. Proof of Concept** | Per-finding: step-by-step exploitation procedures with real commands |
| **Appendix** | Tool list, scan metadata, OWASP distribution chart |

### PoC Generation Engine

The report includes **category-specific PoC procedures** for every finding:

- **SQL Injection** — Manual detection (time-based, error-based) + SQLMap automation + DB enumeration
- **XSS** — Payload injection + cookie theft + session hijacking
- **JWT Attacks** — Token decode + "none" algorithm forge + privilege escalation
- **Command Injection** — Shell metacharacter injection + reverse shell
- **Path Traversal** — File read attempts + config extraction
- **SSRF** — Internal port scan + cloud metadata extraction
- **+ 30+ more categories**

Each PoC includes:
- Real `curl`/`python`/`bash` commands
- Step-by-step exploitation procedure
- Expected output
- Remediation code examples (BAD vs GOOD)

### Visual Design

- **Color-coded severity system** — Critical (Red), High (Orange), Medium (Amber), Low (Blue), Info (Slate)
- **Pill badges** for severity labels
- **Styled section headers** with accent colors
- **Bar charts** for severity distribution
- **OWASP 2025 distribution chart** in appendix
- **Text sanitization** — strips ANSI codes, emojis, binary noise, corrupted fragments
- **Smart page breaks** — prevents text overflow and broken margins
- **Page footers** with page numbers and report metadata

### Noise Filtering

Info-level reconnaissance findings (subdomains, open ports, server headers) are **collapsed into summary tables** rather than listed as full findings — keeping the report focused on actionable vulnerabilities.

---

## 6. Dual RAG Knowledge Bases

The platform fuses **two independent retrieval-augmented generation (RAG) corpora**, both indexed in SQLite FTS5 with BM25 ranking and millisecond retrieval.

### 6.1 PayloadsAllTheThings RAG (PoC Corpus)

### FTS5 Full-Text Search Index

The system builds a **persistent FTS5 (Full-Text Search 5)** index of the PayloadsAllTheThings corpus:

- **201 documents** across **47 vulnerability categories**
- **BM25 ranking** for relevance-scored retrieval
- **Category mapping** — vulnerability type → relevant PoC category
- **Millisecond retrieval** — no re-parsing of markdown on each finding

### Cross-Reference Engine

Every finding is automatically **cross-referenced** against the RAG index:

```
Finding "SQL Injection in /login" 
  → payloadsRag.crossReference(finding)
  → FTS5 search: "SQL Injection"
  → Returns: PoC payloads, attack commands, references
  → Attached to finding as: poc.references[]
```

### Supported Vulnerability Categories (47)

SQL Injection, XSS, Command Injection, SSTI, SSRF, CSRF, LFI/RFI, Path Traversal, File Upload, XXE, IDOR, JWT, NoSQL Injection, LDAP Injection, XPath Injection, Open Redirect, CORS, GraphQL, Deserialization, Prototype Pollution, Race Condition, Request Smuggling, Prompt Injection, WebSocket, OAuth, SAML, CRLF, Type Juggling, Business Logic, Account Takeover, Clickjacking, Zip Slip, API Key Leaks, Web Cache Deception, and more.

### 6.2 Cybersecurity Skills RAG (817 Practitioner Playbooks)

A second RAG corpus built from the **Anthropic-Cybersecurity-Skills** collection (Apache-2.0): **817 practitioner-grade SKILL.md playbooks** across **46 subdomains**, each with YAML frontmatter (name, description, tags) and a structured workflow body (When to Use / Prerequisites / Workflow / Key Concepts / Tools / Common Scenarios / Output Format).

**Lazy-Load Architecture (index.md pattern)**

Instead of flooding the AI context with 817 skills, the system uses a catalog-first pattern:

```
knowledge/skills/index.md   ← generated catalog (817 entries grouped by subdomain)
        │
        ▼  human/AI browses catalog only
FTS5 retrieval (on-demand)  ← query = finding title + CWE + OWASP + description
        │
        ▼  top-2 relevant skills only
DeepSeek verify prompt      ← each playbook body capped at 4KB
```

**Precision Retrieval**

- **Tiered query strategy** — full AND → pairwise AND → OR fallback, so multi-word queries like "cpanel auth bypass" match precisely instead of loosely
- **BM25 column weights** — name (8.0) > tags (4.0) > description (3.0) > subdomain (2.0) > frameworks (1.0) > body (0.5): a skill *named* after the technique always outranks one that merely mentions it
- **Stopword filtering + token length > 2** — removes noise tokens
- **LIKE fallback** — if FTS5 returns nothing, a substring search on name/description/tags guarantees graceful degradation

**Framework Mappings (6 frameworks per skill)**

Every skill carries mappings to **MITRE ATT&CK v19.1, NIST CSF 2.0, MITRE ATLAS, D3FEND, NIST AI RMF, and MITRE F3** — enabling framework-aligned retrieval for compliance-oriented workflows.

**Integration Points**

| Point | Behavior |
|---|---|
| **AI Verification** | `verifyFinding()` injects the top-2 relevant playbooks into the DeepSeek prompt as "REFERENCE PLAYBOOKS" — the specialist agent verifies findings with senior-analyst workflows at hand |
| **Bootstrap** | Index auto-builds on first boot when `skills_index` is empty |
| **API** | `GET /api/skills/status`, `GET /api/skills/search?q=`, `POST /api/skills/reindex` |
| **Catalog** | `writeSkillsCatalog()` regenerates `knowledge/skills/index.md` after every reindex |

**Verified retrieval examples**: "sql injection" → `exploiting-sql-injection-vulnerabilities`; "cpanel auth bypass" → `bypassing-authentication-with-forced-browsing`; "IDOR" → IDOR + BOLA skills; "nmap" → `nmap-advanced`.

---

## 7. OWASP 2025 Top 10 Mapping

### Automatic Categorization

Every finding is automatically mapped to the **OWASP Top 10 (2025 edition)**:

| ID | Category |
|---|---|
| A01 | Broken Access Control |
| A02 | Security Misconfiguration |
| A03 | Software Supply Chain Failures |
| A04 | Cryptographic Failures |
| A05 | Injection |
| A06 | Insecure Design |
| A07 | Authentication Failures |
| A08 | Software or Data Integrity Failures |
| A09 | Security Logging and Alerting Failures |
| A10 | Mishandling of Exceptional Conditions |
| OTH | Others |

### CWE → OWASP Mapping

The system includes a comprehensive **CWE-to-OWASP mapping table** (100+ CWE IDs), ensuring every finding with a CWE identifier is automatically categorized.

### Legacy Migration

Existing findings from older OWASP 2021 categories are automatically migrated to 2025 labels via a `LEGACY_2021_TO_2025` normalization map.

---

## 8. Multi-Provider LLM with Fallback

### 4-Provider Failover Chain

The system uses a **multi-provider LLM client** with automatic failover:

```
1. Bandelbanget AI (DeepSeek V4 Pro) — heavy reasoning tier
       ↓ (if unavailable)
2. OpenRouter AI — fast tier (multiple models)
       ↓ (if unavailable)
3. Groq Cloud AI (Llama 3.3 70B) — fast fallback
       ↓ (if unavailable)
4. Heuristic Engine — deterministic regex-based fallback
```

### Smart Provider Routing

- **Heavy reasoning** (verification, code audit) → Uses heavy tier (Bandelbanget DeepSeek V4 Pro)
- **Fast operations** (chat, summaries) → Uses fast tier (OpenRouter/Groq)
- **Automatic retry** with exponential backoff on 429/5xx errors
- **Health checking** — `checkProvidersHealth()` endpoint shows real-time provider status

### Token Usage Tracking

The system tracks **token usage** per scan and displays it in the UI, so users can monitor AI consumption costs.

---

## 9. Real-Time Live Streaming

### WebSocket Architecture

All scan activity is streamed in real-time via **Socket.IO** with JWT-authenticated connections:

| Event | Payload | When |
|---|---|---|
| `scan:log` | `{scanId, level, message, ts}` | Every log line |
| `scan:update` | `{scanId, progress, status?}` | Progress % change (throttled 250ms) |
| `scan:finding` | `{scanId, finding}` | New finding completes enrichment |
| `scan:done` | `{scanId, status, scan, counts, riskScore}` | Pipeline finishes |

### Live Features

- **Live Terminal Output** — Real-time scan log stream with color-coded log levels
- **Live Findings Stream** — Findings appear as they're discovered and verified
- **Live Progress Bar** — Animated progress with risk score display
- **Live Exploit Progress** — Campaign steps update in real-time (queued → running → completed/failed)
- **Live Monitor Events** — Scheduled rescan results stream to the Monitoring page

### Fish Audio Executive Briefing

After a scan completes, users can click **"Audio Briefing"** to hear an AI-generated executive summary of the scan results, powered by Fish Audio TTS (Text-to-Speech) via OpenRouter.

---

## 10. GitHub CI/CD Integration

### Automated Security Scanning

The system integrates with GitHub for **continuous security automation**:

- **Push Triggers** — Automatically scan code on every push to tracked repositories
- **Pull Request Triggers** — Scan PRs before merge
- **Webhook Processing** — Parse GitHub webhook events and trigger scans
- **Repository Listing** — Browse and track repositories via GitHub API
- **Source Code Ingestion** — Fetch repository tree and source files for whitebox analysis

### GitHub Automation Page

The frontend includes a dedicated **GitHub Automation** page where users can:
- Connect their GitHub account via Personal Access Token
- Browse all their repositories
- Track/untrack repositories for automatic scanning
- Configure per-repo settings (auto-scan on push, auto-scan on PR, email reports)
- View webhook setup guide
- Manually trigger scans on any repository

### Smart File Filtering

The GitHub integration automatically filters out:
- Binary files (images, videos, fonts, archives)
- Dependency directories (node_modules, vendor, .git)
- Lock files (package-lock.json, yarn.lock, etc.)
- Minified files (.min.js, .min.css)
- Files exceeding 150KB

---

## 11. Billing & Subscription System

### Tiered Subscription Plans

| Plan | Price | Scans/mo | Repos | Key Features |
|---|---|---|---|---|
| **Pro** | $19/mo | 50 | 5 | AI Code Audits, Webhooks, Email PDF Delivery, AI Auto-Fix |
| **Enterprise** | $79/mo | Unlimited | Unlimited | PR Bot, Slack/Discord Webhooks, White-label Reports, 24/7 SLA |

### Payment Integration

- **Stripe** — Credit card payments
- **LemonSqueezy** — Alternative payment processor
- **ToyyibPay** — Malaysian payment gateway
- **Manual** — Admin-initiated plan activation

### Quota Enforcement

The system enforces scan quotas per subscription plan — users exceeding their quota are prompted to upgrade.

---

## 12. Security & Privacy Hardening

### Data Privacy

- **Secret/PII Redaction** — All secrets, API keys, JWTs, private keys, database connection strings, and emails are redacted BEFORE being sent to LLM providers
- **Sandbox Wiping** — Temporary sandboxes are wiped after analysis
- **Local-First** — All data stays in local SQLite database, no cloud DB required

### Platform Security

- **CORS Lockdown** — Whitelist-based origin checking
- **Login Rate Limiting** — 10 attempts per 15 minutes per IP
- **WebSocket JWT Auth** — Every socket connection is JWT-authenticated
- **Security Headers** — X-Content-Type-Options, X-Frame-Options, Referrer-Policy
- **Password Hashing** — bcryptjs with salt rounds
- **Audit Logging** — All administrative actions logged to `audit` table

### False Positive Prevention

The system employs multiple layers to prevent false positives:

1. **Precision Mode AI Prompts** — "ONLY REPORT CONFIRMED VULNERABILITIES"
2. **Heuristic Verification** — 12+ true-positive patterns, 4 false-positive patterns
3. **Severity Bounds Enforcement** — Caps severity for low-impact categories
4. **Confidence Thresholds** — Auto-exploit only triggers at confidence ≥ 70%
5. **Agent Persona Sanitization** — Strips "FULL OFFENSIVE" directives that cause over-reporting
6. **Deduplication** — Fingerprint-based dedup prevents duplicate findings

---

## 13. Frontend Feature Showcase

### Pages (15)

| Page | Features |
|---|---|
| **Landing** | Marketing landing page with feature showcase |
| **Login** | JWT authentication with rate-limited login |
| **Dashboard** | Aggregate stats, recent scans, risk overview |
| **Scans** | Scan list with status, risk score, findings count |
| **Scan Detail** | Live terminal, live findings, progress bar, pause/resume/stop, audio briefing, structural mapping, console terminal, report download |
| **Findings** | Filterable finding cards with severity badges, status triage |
| **Projects** | Project CRUD with risk level, scope, linked scans |
| **Monitoring** | Scheduled rescan monitors with event feed |
| **Exploits** | Exploit campaign list with live step progress |
| **Exploit Campaign** | Detailed campaign view with step-by-step execution, loot, approval gates |
| **GitHub Automation** | Repository tracking, webhook config, auto-scan settings |
| **Billing** | Subscription plans, payment checkout, transaction history |
| **Settings** | Profile management, password change, system status |
| **Integrations** | Engine status, AI provider health, RAG index, agent list |

### Components (10)

| Component | Purpose |
|---|---|
| **Shell** | Sidebar navigation layout with New Scan trigger |
| **NewScanModal** | Blackbox/whitebox scan launch form with depth selection |
| **SeverityBadge** | Color-coded severity pill with inline severity change |
| **FindingDetailDrawer** | Slide-over panel: Overview / PoC / CVE / Notes tabs |
| **AIChatWidget** | Floating global AI chat (all pages) with 50 agent selection |
| **ReportModal** | PDF report generation and download |
| **StructuralMappingView** | Visual attack surface mapping with finding correlation |
| **StatCard** | Dashboard statistics card |
| **InspectorLogo** | Platform branding |
| **RequestScanModal** | Client scan request form with email notification |

### Scan Detail Page — The Crown Jewel

The Scan Detail page is the most feature-rich page in the platform:

- **Live Terminal** — Real-time scan output with color-coded log levels
- **Live Findings** — Findings stream in as they're discovered, with search and severity filter
- **Progress Bar** — Animated progress with risk score and token usage display
- **Pause / Resume / Stop** — Full scan lifecycle control
- **Retry Failed** — Re-run only failed tools/passes
- **Audio Briefing** — Fish Audio TTS executive summary
- **Structural Mapping** — Visual attack surface map
- **Report Download** — Generate and download PDF report
- **Whitebox Audit Details** — Files checked, scan passes, pass status, duration
- **Blackbox URL Tracking** — URLs scanned, tools executed, subdomains discovered
- **Console Terminal** — Run commands (nmap, curl, hydra) against the target directly from the UI
- **Finding Detail Drawer** — Click any finding for full details with PoC, CVE lookup, and analyst notes

---

## 14. Technology Stack

### Backend

| Technology | Purpose |
|---|---|
| **Node.js** | Runtime (ESM modules) |
| **Express** | REST API server |
| **Socket.IO** | Real-time WebSocket communication |
| **better-sqlite3** | Embedded SQLite database (WAL mode, FTS5) |
| **PDFKit** | PDF report generation |
| **bcryptjs** | Password hashing |
| **jsonwebtoken** | JWT authentication |
| **express-rate-limit** | API rate limiting |
| **nodemailer** | Email notifications |
| **swagger-ui-express** | API documentation |

### Frontend

| Technology | Purpose |
|---|---|
| **React 18** | UI framework |
| **Vite** | Build tool & dev server |
| **Tailwind CSS** | Utility-first styling |
| **React Router** | Client-side routing |
| **Socket.IO Client** | WebSocket client |
| **lucide-react** | Icon library |

### External Integrations

| Integration | Purpose |
|---|---|
| **Hexstrike-AI** | 100+ security tool engine (REST) |
| **OpenRouter** | LLM provider (fast tier) |
| **Bandelbanget AI** | LLM provider (heavy tier, DeepSeek V4 Pro) |
| **Groq Cloud** | LLM provider (fallback, Llama 3.3 70B) |
| **NIST NVD API** | CVE lookup and enrichment |
| **Metasploit RPC** | Exploitation framework |
| **GitHub API** | Repository ingestion & webhooks |
| **Fish Audio** | Text-to-Speech executive briefings |
| **Stripe** | Payment processing |
| **SMTP** | Email notifications |

### Database Schema (22 tables)

```
users, projects, scans, findings, logs, payload_index, payload_fts,
skills_index, skills_fts,
audit, monitors, monitor_events, finding_notes, cve_cache,
exploit_campaigns, exploit_steps, exploit_loot, exploit_approvals,
github_integrations, github_repos, scan_configs, subscriptions,
payment_transactions, ai_prompt_adjustments, ai_feedback_reviews
```

---

## System Statistics

| Metric | Value |
|---|---|
| Specialist AI Agents | 50 |
| Security Tools (via Hexstrike) | 100+ |
| RAG Knowledge Documents | 201 PoC + 817 skills |
| RAG Skill Subdomains | 46 |
| Vulnerability Categories (PoC) | 47 |
| Framework Mappings per Skill | 6 (ATT&CK, NIST CSF, ATLAS, D3FEND, AI RMF, F3) |
| OWASP 2025 Categories | 10 + OTH |
| CWE Mappings | 100+ |
| REST API Endpoints | 90+ |
| Database Tables | 22 |
| Frontend Pages | 15 |
| Frontend Components | 10 |
| LLM Providers | 4 (with failover) |
| Exploit Techniques | 15+ registered |
| Post-Exploit Actions | 5 categories |
| AI Self-Correction Error Types | 10 |

---

> **SentinelAI** — _From reconnaissance to exploitation to reporting, fully autonomous, fully local._
