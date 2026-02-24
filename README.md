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

## tambah sqlite untuk save backend