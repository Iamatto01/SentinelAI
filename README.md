# SentinelAI

Full working project built from the **lol UI** (static multi-page Tailwind UI) + a local **Express + Socket.IO** backend.

## What’s inside

- `frontend/` — The React client (Tailwind UI)
- `backend/` — Express backend (simulated scan, API, socket.io)
- `ai_agents/` — Python CrewAI bridge for intelligent security analysis

## Run with Docker (Recommended)

The easiest way to run SentinelAI with all its components (Frontend, Backend, and AI Agents) is using Docker Compose.

1. **Set up environment variables:**
   ```bash
   cp .env.example .env
   ```
   *Edit `.env` and add your `GROQ_API_KEY` to enable AI features.*

2. **Build and start the containers:**
   ```bash
   docker compose up --build
   ```

3. **Open the app:**
   Go to http://localhost:5000 in your browser.

To stop the application, press `Ctrl+C` or run:
```bash
docker compose down
```

---

## Run Locally (Manual Setup)

### Option A: Run using npm (concurrently)

From the project root, you can install dependencies and run both frontend and backend together:

```powershell
npm run install:all
npm run dev
```

### Option B: Run services separately

1) Start the backend:

```powershell
cd backend
npm install
npm run dev
```

2) Start the React dev server (in a separate terminal):

```powershell
cd frontend
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


Approach: Browser-Native Web Speech API (100% Free, No Server Cost)
We will use the Web Speech API built into modern browsers (Chrome, Edge, Safari):

Feature	API	Cost	Browser Support
STT	SpeechRecognition / webkitSpeechRecognition	Free	Chrome, Edge, Safari
TTS	speechSynthesis	Free	All modern browser