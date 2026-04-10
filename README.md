# SentinelAI

Full working project built from the **lol UI** (static multi-page Tailwind UI) + a local **Express + Socket.IO** backend.

## What’s inside

- `public/` — the UI copied from `lol/` and wired to the backend via `/api/*`
- `server/` — Express backend (safe simulated scan + sample data)

## Run

### Option A (recommended): run the server directly

```powershell
Set-Location "f:\FYP\vlolv\server"
node src\index.js
```

Then open:

- http://localhost:5000/index.html
- http://localhost:5000/v2/index.html

### Option B: npm scripts (if you prefer)

```powershell
Set-Location "f:\FYP\vlolv\server"
npm run dev
```

## React (new UI)

The React client lives in `client-react/`.

1) Start the backend:

```powershell
Set-Location "f:\FYP\vlolv\server"
npm install
npm run dev
```

2) Start the React dev server (in a separate terminal):

```powershell
Set-Location "f:\FYP\vlolv\client-react"
npm install
npm run dev
```

Then open the URL shown by Vite (usually `http://localhost:5173/`).

## Notes

- The UI auto-logs in using a local dev user (`admin` / `admin`) and stores a bearer token in `localStorage`.
- The **Live Scan** page uses Socket.IO (`/socket.io/*`) to receive `scan:update` events.
- This backend only simulates scan progress/logs and returns demo vulnerabilities. It does **not** run real scans.

## HTTPS setup

The backend can run over HTTPS if you provide certificate files:

```bash
HTTPS_KEY_PATH=/path/to/privkey.pem
HTTPS_CERT_PATH=/path/to/fullchain.pem
# Optional:
HTTPS_CA_PATH=/path/to/ca.pem
```

When those variables are set, the backend serves the app over `https://` on the same `PORT`.

For Vite dev proxying against an HTTPS backend, set:

```bash
VITE_BACKEND_TARGET=https://localhost:5000
VITE_PROXY_SECURE=false
```

Set `VITE_PROXY_SECURE=false` only for self-signed local certificates. Keep it enabled for real public certificates.

## tambah sqlite untuk save backend
sudo apt update
sudo apt install -y nmap nikto whatweb sqlmap sslscan gobuster wafw00f wpscan nuclei ffuf feroxbuster dnsrecon fierce amass wapiti
pipx install sublist3r || pip3 install --user sublist3r
go install github.com/hahwul/dalfox/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/OWASP/Amass/v4/...@master

Optional tools that may need separate install:

Commix
Arjun
testssl.sh