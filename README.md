# Rakshak SOC v2 — SIEM Dashboard

## Project Structure
```
rakshak-soc/
├── index.html          ← Main dashboard (auth gate + full app shell)
├── login.html          ← Standalone login page (for Vercel /api/auth flow)
├── styles.css          ← Complete design system (60:30:10 palette)
├── app.js              ← All SIEM logic (charts, alerts, triage, upload)
├── data/
│   └── sample-logs.json  ← 77 realistic security events (REQUIRED)
├── package.json
└── vercel.json         ← Routes: /login, /api/auth, /api/reviews
```

## Running Locally
```bash
# Serve with any static server — must use HTTP (not file://)
npx serve .          # or
python3 -m http.server 3000
# then open http://localhost:3000
```

> **Important:** Open via `http://localhost` not `file://` — the app
> fetches `./data/sample-logs.json` which requires HTTP.

## Deploy to Vercel
```bash
npm i -g vercel
vercel deploy
```

## Password
`jimil`

## Features
- Sidebar navigation: Overview · Alert Queue · Event Stream · Threat Intel · MITRE ATT&CK · Log Ingest · Reports
- KPI metrics, category/severity/trend charts
- MITRE ATT&CK attack path visualization
- Asset exposure + dwell-time forecasting
- Live alert triage (TP/FP verdicts, notes, reports)
- Real log ingestion (JSON, NDJSON, CSV, TXT drag-and-drop)
- Time range filtering (24h, 3d, 7d, All Time, custom dates)
- Auto-stream simulation mode
