# 🏛️ Sentinel Trust Bank — Commercial & Digital Banking Portal (OWASP Testbed)

A realistic, full-featured commercial and digital banking application built as a vulnerable benchmark testbed for automated vulnerability scanners (**SentinelAI**, Nuclei, Nikto, SQLmap, Dalfox, Arjun, etc.) and offensive security evaluations.

Styled realistically as a modern financial institution (**Sentinel Trust Bank, N.A.**) featuring personal checking, high-yield commercial reserve accounts, Fedwire/SWIFT cross-border clearing, KYC onboarding verification, and internal NOC diagnostics.

---

## 🚀 Quick Start

### Option 1: Run Locally on Windows
```bash
cd vulnerable-target
npm install
npm start
```
The application will start on **`http://localhost:8080`**.

---

### Option 2: Run on Kali Linux Server
```bash
# SSH into Kali
cd /home/kali/server/SentinelAI/vulnerable-target
npm install
node server.js &
```
The application will be accessible at: **`http://localhost:8080`** or **`https://abuse.sentinelai.studio`** via Cloudflare Tunnel.

---

## 🏛️ Realistic Banking Architecture & Mapping to Vulnerabilities

| Banking Feature & Route | Realistic Context | OWASP 2021 | Vulnerability Category |
|---|---|---|---|
| **`/login.html`** (`POST /api/login`) | Commercial Online Banking Sign-In | A03 / CWE-89 | **SQL Injection (Auth Bypass)** |
| **`/login.html`** (`GET /api/products/search?q=`) | Commercial Products & Yield Rates Search | A03 / CWE-89 | **SQL Injection (UNION Exfiltration)** |
| **`/search?q=`** | Financial Catalog Search Term Reflection | A03 / CWE-79 | **Reflected Cross-Site Scripting (XSS)** |
| **`/feedback.html`** (`POST /api/feedback`) | Client Experience & Branch Review Board | A03 / CWE-79 | **Stored Cross-Site Scripting (XSS)** |
| **`/admin.html`** (`GET /api/tools/ping?host=`) | NOC ATM Switch & Routing Health Ping | A03 / CWE-78 | **Command Injection (RCE)** |
| **`/documents.html`** (`GET /api/documents/view?file=`) | Regulatory Disclosures & E-Statement Archive | A01 / CWE-22 | **Path Traversal / Local File Inclusion** |
| **`/profile.html`** (`GET /api/orders/:id`) | Interbank Fedwire Transfer Receipts | A01 / CWE-639 | **IDOR (Wire Settlement Leakage)** |
| **`/profile.html`** (`GET /api/users/:id`) | Account Holder Profiles & Card Records | A01 / CWE-200 | **IDOR (Credit Card & Token Disclosure)** |
| **`/upload.html`** (`POST /api/upload`) | Client Onboarding & KYC Document Verification | A04 / CWE-434 | **Unrestricted File Upload / Web Shells** |
| **`/ssrf.html`** (`GET /api/proxy-fetch?url=`) | Interbank Foreign Exchange & Clearing Proxy | A10 / CWE-918 | **Server-Side Request Forgery (SSRF)** |
| **`/.env`** | Production Environment Secrets | A05 / CWE-200 | **Sensitive Information Disclosure** |
| **`/backup.sql`** | Core Banking Database Dump | A05 / CWE-200 | **Database Backup Exposure** |
| **`/actuator/env`** | Spring Boot Actuator Infrastructure Disclosure | A05 / CWE-200 | **Environment Metric Disclosure** |

---

## 🎯 How to Scan with SentinelAI

1. Open your SentinelAI dashboard at `https://sentinelai.studio` (or `http://localhost:5173`).
2. Click **+ New Scan**.
3. Enter Target URL:
   ```
   https://abuse.sentinelai.studio
   ```
   *(Or `http://127.0.0.1:8080` if running locally)*.
4. Select Mode: **Full Blackbox** or **Standard Scan**.
5. Launch scan! SentinelAI's autonomous engines will discover and exploit the banking application vulnerabilities automatically.
