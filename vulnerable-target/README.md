# 🛡️ VulnCorp — Vulnerable Target Web Application (OWASP Testbed)

A modern, full-featured vulnerable web application built for testing penetration testing platforms, automated vulnerability scanners (**SentinelAI**, Nuclei, Nikto, SQLmap, Dalfox, Arjun, etc.), and whitebox/blackbox audit workflows.

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

### Option 2: Run on Kali Linux Server (`192.168.31.128`)
You can run it as a background service on the Kali Linux server:
```bash
# SSH into Kali
ssh kali@192.168.31.128
cd /home/kali/server/SentinelAI/vulnerable-target
npm install
node server.js &
```
The application will be accessible at: **`http://192.168.31.128:8080`**

---

## 🧪 Summary of Included Vulnerabilities & Attack Vectors

| # | Vulnerability Category | OWASP 2021 | Endpoint / Parameter | Test Payload |
|---|------------------------|------------|----------------------|--------------|
| 1 | **SQL Injection (Auth Bypass)** | A03 / CWE-89 | `POST /api/login` (`username`) | `admin' --` or `admin' OR 1=1 --` |
| 2 | **SQL Injection (Search)** | A03 / CWE-89 | `GET /api/products/search?q=` | `' UNION SELECT 1,username,password,credit_card,email FROM users--` |
| 3 | **Command Injection (RCE)** | A03 / CWE-78 | `GET /api/tools/ping?host=` | `127.0.0.1; whoami` or `127.0.0.1 && id` |
| 4 | **Reflected XSS** | A03 / CWE-79 | `GET /search?q=` | `<script>alert(document.domain)</script>` |
| 5 | **Stored XSS** | A03 / CWE-79 | `POST /api/feedback` (`comment`) | `<img src=x onerror="alert(document.cookie)">` |
| 6 | **Path Traversal / LFI** | A01 / CWE-22 | `GET /api/documents/view?file=` | `../../documents/company_secret.txt` or `../../../../etc/passwd` |
| 7 | **IDOR (Broken Access Control)** | A01 / CWE-639 | `GET /api/orders/:id` | `GET /api/orders/1`, `GET /api/orders/2` |
| 8 | **Sensitive User Data Leakage** | A01 / CWE-200 | `GET /api/users/:id` | `GET /api/users/1` (leaks credit cards & MD5 hashes) |
| 9 | **Server-Side Request Forgery (SSRF)** | A10 / CWE-918 | `GET /api/proxy-fetch?url=` | `http://127.0.0.1:8080/api/users/1` |
| 10 | **Hardcoded Secrets & Config Leak** | A05 / CWE-200 | `GET /.env` | Direct access to DB passwords, AWS keys, Stripe tokens |
| 11 | **Database Backup Exposure** | A05 / CWE-200 | `GET /backup.sql` | Direct access to SQL schema and user data dump |
| 12 | **Spring Actuator Disclosure** | A05 / CWE-200 | `GET /actuator/env` | Exposes internal environment properties |
| 13 | **Insecure Session Cookie** | A07 / CWE-1004 | `Set-Cookie` on `/api/login` | Missing `HttpOnly`, `Secure`, `SameSite` flags |
| 14 | **Missing Security Headers** | A05 / CWE-16 | All responses | No CSP, no X-Frame-Options (Clickjacking testable), no HSTS |
| 15 | **Technology Banner Disclosure** | A05 / CWE-200 | All responses | `Server: Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1d`, `X-Powered-By: Express` |

---

## 🎯 How to Scan with SentinelAI

1. Open your SentinelAI dashboard at `http://192.168.31.128:5173/app/scans` (or `http://localhost:5173/app/scans`).
2. Click **+ New Scan**.
3. Enter Target URL:
   ```
   http://192.168.31.128:8080
   ```
   *(Or `http://127.0.0.1:8080` if running locally)*.
4. Select Mode: **Full Blackbox** or **Standard Scan**.
5. Launch scan! SentinelAI's autonomous engines (Nikto, Nuclei, Katana, ffuf, SQLMap, Dalfox) will discover and map all 15+ vulnerabilities automatically.
