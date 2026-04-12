<div align="center">

<br />

```
██████╗  █████╗ ██╗  ██╗███████╗██╗  ██╗ █████╗ ██╗  ██╗    ███████╗ ██████╗  ██████╗
██╔══██╗██╔══██╗██║ ██╔╝██╔════╝██║  ██║██╔══██╗██║ ██╔╝    ██╔════╝██╔═══██╗██╔════╝
██████╔╝███████║█████╔╝ ███████╗███████║███████║█████╔╝     ███████╗██║   ██║██║
██╔══██╗██╔══██║██╔═██╗ ╚════██║██╔══██║██╔══██║██╔═██╗     ╚════██║██║   ██║██║
██║  ██║██║  ██║██║  ██╗███████║██║  ██║██║  ██║██║  ██╗    ███████║╚██████╔╝╚██████╗
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝  ╚═════╝
```

### Security Operations Center · SIEM Dashboard

*रक्षक — Sanskrit for Guardian*

<br />

[![Live Demo](https://img.shields.io/badge/▶_Live_Demo-000000?style=for-the-badge&logo=vercel&logoColor=white)](https://your-project.vercel.app)
&nbsp;
[![MIT License](https://img.shields.io/badge/License-MIT-16A34A?style=for-the-badge)](LICENSE)
&nbsp;
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-E84545?style=for-the-badge)](https://attack.mitre.org)
&nbsp;
[![Vanilla JS](https://img.shields.io/badge/Vanilla_JS-No_Framework-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)](https://developer.mozilla.org/docs/Web/JavaScript)

<br />

> A fully functional, browser-based SIEM dashboard with real SOC analyst workflows —
> alert triage · MITRE ATT&CK mapping · threat intel · live log ingestion.
> **No backend. No framework. No build tools. Just open and ship.**

<br />

</div>

---

## What Is This

**Rakshak SOC** is a self-contained Security Information and Event Management (SIEM) dashboard simulation that runs entirely in the browser. It was built to demonstrate real Security Operations Center workflows without requiring Splunk, Elastic, or any enterprise tooling.

If you are learning SOC analysis, studying for a blue team certification, or building a cybersecurity portfolio — this project gives you a working, interactive environment to understand **how analysts think and work**.

---

## Features

### Core Dashboard

| Feature | Description |
|---|---|
| **KPI Metrics** | Live counts — total events, active window, alert queue, investigated cases |
| **Threat Category Volume** | Interactive bar chart — click any category to filter the entire dashboard |
| **Severity Breakdown** | Three chart views: Donut · Bar · Histogram. Click any severity to drill down into its alerts |
| **Daily Threat Trend** | Click any day column to isolate that single date across all panels |
| **Activity Timeline** | Real-time tile stream of ingested telemetry — click any tile for full event detail |

### Alert Management

| Feature | Description |
|---|---|
| **Active Alert Queue** | Auto-generated alerts from correlation rules — brute force detection, direct IOC matches |
| **Investigated Cases** | Saved TP/FP verdicts are separated from the active queue automatically |
| **Investigation Detail** | Full alert context — rule, source, target, related events, recommended action |
| **Analyst Triage** | Set verdict (True Positive / False Positive / Needs Review), write analyst notes |
| **Report Generation** | One-click Markdown report per alert — copy to clipboard or download `.md` file |
| **Bulk Export** | Export all investigated cases as a single investigation report |

### Threat Intelligence

| Feature | Description |
|---|---|
| **Asset Criticality vs Exposure** | Predictive scoring of assets by criticality, vulnerability pressure, and live targeting likelihood |
| **Projected Dwell Time** | Estimates how long an attacker could stay undetected per subnet if breached today |

### MITRE ATT&CK

| Feature | Description |
|---|---|
| **Attack Path Visualization** | Full 10-stage kill chain — Reconnaissance → Impact — mapped from live telemetry |
| **Technique Attribution** | Each event maps to a specific ATT&CK technique (e.g. PowerShell → T1059.001) |
| **Chain Confidence Score** | Percentage score indicating how complete the observed kill chain is |
| **Interactive Nodes** | Click any tactic node to filter all dashboard data to that technique |

### Log Ingestion

| Feature | Description |
|---|---|
| **Drag and Drop** | Drop a log file directly onto the dashboard |
| **Multi-format Support** | JSON array · NDJSON · CSV with headers · plain TXT |
| **Live Merge** | Imported logs merge with existing telemetry in real time |
| **Auto Normalization** | Field mapping (timestamp, severity, category) is inferred automatically |

### Controls & Filtering

| Feature | Description |
|---|---|
| **Time Range Presets** | 24h · 3d · 7d · All Time — one click |
| **Custom Date Range** | Pick exact start and end dates |
| **Severity Filter** | Filter all panels to Critical / High / Medium / Low |
| **Category Filter** | Filter by event category (identity, malware, cloud, etc.) |
| **Global Search** | Search across source, target, message, and event type simultaneously |
| **Auto Stream** | Simulates a live feed — injects new threat scenarios every 4 seconds |
| **Incident Simulation** | Inject pre-built realistic attack scenarios on demand |

### UI / UX

| Feature | Description |
|---|---|
| **Dark / Light Mode** | Full theme switch — persists in `localStorage`, respects OS preference |
| **Collapsible Sidebar** | Collapses to icon-only rail on desktop |
| **Mobile Responsive** | 4 breakpoints — works on phone, tablet, and desktop |
| **Mobile FAB Bar** | Floating action bar on small screens for key controls |
| **Smooth Animations** | Staggered card entrance, chart transitions, sidebar slide |
| **Zero Flash** | Theme is applied before paint — no white-to-dark flicker |

---

## Tech Stack

```
Language       Vanilla JavaScript (ES2022) — zero dependencies
Styling        Pure CSS with custom properties (no Tailwind, no preprocessor)
Fonts          Syne · DM Sans · JetBrains Mono (Google Fonts)
Charts         Hand-built with CSS (donut via conic-gradient, bars via flexbox)
Auth           Client-side password gate + sessionStorage
Storage        localStorage for alert reviews + optional Vercel Blob API
Deploy         Vercel (static) — any static host works
```

No React. No Vue. No webpack. No npm build step. One HTML file, one CSS file, one JS file.

---

## Project Structure

```
rakshak-soc/
│
├── index.html              ← Auth gate + full app shell (7 sections)
├── styles.css              ← Complete design system (light + dark tokens)
├── app.js                  ← All SIEM logic — alerts, charts, triage, ingestion
│
├── data/
│   └── sample-logs.json    ← 77 realistic security events (REQUIRED for load)
│
├── login.html              ← Standalone login page (for Vercel /api/auth flow)
├── vercel.json             ← URL rewrites for /login and /api/* routes
└── package.json            ← Minimal — only @vercel/blob for review storage
```

> **Critical:** `data/sample-logs.json` must exist. The app fetches it on load.
> Remove it and every chart will be empty.

---

## Quick Start

### Option 1 — npx serve (recommended)

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/rakshak-soc.git
cd rakshak-soc

# Serve (requires Node.js)
npx serve .
```

Open [http://localhost:3000](http://localhost:3000)

### Option 2 — Python

```bash
python3 -m http.server 3000
```

Open [http://localhost:3000](http://localhost:3000)

### Option 3 — VS Code Live Server

Install the **Live Server** extension → right-click `index.html` → **Open with Live Server**

> **Why not `file://`?**
> The app fetches `./data/sample-logs.json` on startup. Browsers block
> cross-origin `fetch()` on `file://` protocol. Always use a local HTTP server.

### Login

```
Password: jimil
```

---

## Deploy to Vercel

```bash
# Install Vercel CLI
npm install -g vercel

# Deploy from project root
vercel deploy
```

Vercel reads `vercel.json` and automatically routes:

| URL | Serves |
|---|---|
| `/` | `index.html` |
| `/login` | `login.html` |
| `/api/auth` | `api/auth.js` |
| `/api/reviews` | `api/reviews.js` |

For review persistence on Vercel, add a **Blob store** in your Vercel project settings. Without it, reviews save to `localStorage` only — fully functional but not shared across sessions.

---

## Log Ingestion

Rakshak SOC accepts real security logs. Drag and drop any of these formats onto the **Log Ingest** section:

### Supported Formats

**JSON Array**
```json
[
  {
    "timestamp": "2024-12-15T10:30:00Z",
    "event_type": "failed_login",
    "source": "192.168.1.50",
    "target": "vpn-gateway",
    "severity": "high",
    "status": "investigate",
    "message": "Multiple authentication failures",
    "category": "identity"
  }
]
```

**NDJSON (one object per line)**
```
{"timestamp":"2024-12-15T10:30:00Z","event_type":"port_scan","source":"10.0.4.22","target":"SRV-DB-01","severity":"medium","status":"investigate","message":"Horizontal scan detected","category":"reconnaissance"}
{"timestamp":"2024-12-15T10:31:00Z","event_type":"malware_detected","source":"WS-FIN-07","target":"endpoint-protection","severity":"critical","status":"contained","message":"Trojan dropper detected","category":"malware"}
```

**CSV with headers**
```csv
timestamp,event_type,source,target,severity,status,message,category
2024-12-15T10:30:00Z,web_attack,45.155.205.10,portal.company.local,high,escalated,SQL injection attempt,application
```

### Field Mapping

The ingestion pipeline auto-normalizes these aliases:

| Field | Accepted Aliases |
|---|---|
| `timestamp` | `time`, `date`, `datetime`, `event_time` |
| `event_type` | `eventtype`, `type`, `event`, `activity`, `signature` |
| `source` | `src`, `source_ip`, `host`, `hostname`, `client_ip` |
| `target` | `dst`, `destination`, `dest_ip`, `service`, `user` |
| `severity` | `level`, `priority`, `risk`, `score` |
| `message` | `msg`, `description`, `details`, `summary` |

---

## MITRE ATT&CK Mapping

Every event type maps to a specific ATT&CK tactic and technique:

| Event Type | Tactic | Technique |
|---|---|---|
| `port_scan` | Reconnaissance | T1595 — Active Scanning |
| `web_attack` | Initial Access | T1190 — Exploit Public-Facing Application |
| `failed_login` | Initial Access | T1078 — Valid Accounts |
| `geo_impossible_travel` | Initial Access | T1078 — Valid Accounts |
| `powershell_abuse` | Execution | T1059.001 — PowerShell |
| `malware_detected` | Execution | T1204 — User Execution |
| `registry_persistence` | Persistence | T1547 — Registry Run Keys |
| `privilege_escalation` | Privilege Escalation | T1098 — Account Manipulation |
| `service_disabled` | Defense Evasion | T1562 — Impair Defenses |
| `lateral_movement` | Lateral Movement | T1021 — Remote Services |
| `dns_tunnel` | Command & Control | T1071 — DNS |
| `beaconing` | Command & Control | T1071 — Application Layer Protocol |
| `data_exfiltration` | Exfiltration | T1041 — Exfil Over C2 Channel |
| `container_escape` | Impact | T1611 — Escape to Host |
| `file_integrity` | Impact | T1565 — Data Manipulation |

---

## Sample Data

The bundled `data/sample-logs.json` contains **77 realistic security events** spanning a 7-day incident timeline (Dec 10–16, 2024):

```
Events       77 records across 7 days
Categories   12 — application, cloud, command-and-control, defense-evasion,
                  execution, exfiltration, identity, malware, movement,
                  persistence, privilege, reconnaissance
Severities   Critical · High · Medium
Event Types  15 unique types — all MITRE ATT&CK mapped
Scenarios    Multi-stage APT simulation, ransomware drop, credential stuffing,
             container escape, lateral movement chain, C2 beaconing
```

The events are designed to trigger correlation rules — brute force detection
(3+ failed logins from same source), port scan clustering, and direct
detection on all 13 high-fidelity event types.

---

## Correlation Rules

Alerts are generated automatically by three rule types:

**Direct Detection** — Any of these event types immediately creates an alert:
```
malware_detected  powershell_abuse  registry_persistence  lateral_movement
container_escape  data_exfiltration privilege_escalation  dns_tunnel
beaconing         web_attack        file_integrity        geo_impossible_travel
service_disabled
```

**Brute Force Correlation** — 3+ failed logins from the same source to the same target within the active time window → Alert (severity scales with count: 3+ = High, 5+ = Critical)

**Port Scan Pattern** — 2+ port scan events from the same source → Medium alert tagged Reconnaissance

---

## Screenshots

> Replace these placeholders with actual screenshots of your deployment.

| Light Mode | Dark Mode |
|---|---|
| ![Light](https://placehold.co/440x280/F7F6F3/1C1C1E?text=Light+Mode) | ![Dark](https://placehold.co/440x280/0F0F11/F0F0F5?text=Dark+Mode) |

| Alert Queue | MITRE ATT&CK |
|---|---|
| ![Alerts](https://placehold.co/440x280/F7F6F3/E84545?text=Alert+Queue) | ![MITRE](https://placehold.co/440x280/F7F6F3/2563EB?text=MITRE+ATT%26CK) |

| Mobile View | Log Ingest |
|---|---|
| ![Mobile](https://placehold.co/220x380/0F0F11/F0F0F5?text=Mobile) | ![Ingest](https://placehold.co/440x280/F7F6F3/16A34A?text=Log+Ingest) |

---

## Roadmap

- [x] MITRE ATT&CK full 10-stage kill chain mapping
- [x] Alert triage with TP/FP verdict system
- [x] Analyst notes + Markdown report export
- [x] Real log ingestion (JSON, NDJSON, CSV)
- [x] Asset exposure scoring + dwell-time forecasting
- [x] Dark / Light mode with OS preference detection
- [x] Full mobile responsiveness (4 breakpoints)
- [x] Auto-stream simulation mode
- [ ] Sigma rule editor and evaluator
- [ ] SPL-style query bar for ad-hoc log search
- [ ] VirusTotal / AbuseIPDB threat intel lookups (API integration)
- [ ] Persistent multi-user reviews via Vercel Blob
- [ ] CSV / PDF report export
- [ ] Email alerting via Resend API
- [ ] Webhook integration (Slack / Discord notifications)
- [ ] CVSS scoring on asset vulnerabilities

---

## Learning SOC Concepts

This project was built to learn — here's what each feature maps to in real-world SOC work:

| This Project | Real SOC Equivalent |
|---|---|
| Alert Queue | Splunk Enterprise Security · Microsoft Sentinel Incidents |
| MITRE ATT&CK mapping | MITRE Navigator · Elastic Security detection rules |
| TP/FP verdict + notes | ServiceNow ticket · Jira incident record |
| Correlation rules | Sigma rules · SPL searches · KQL detection queries |
| Log ingestion pipeline | Splunk Universal Forwarder · Elastic Beats · Logstash |
| Asset exposure model | Tenable.io · Qualys vulnerability scoring |
| Dwell time forecast | Mean Time to Detect (MTTD) metrics |
| Report export | SOC runbook documentation · Chain of custody |

### Recommended Next Steps

If this project sparked your interest in SOC work:

- **[TryHackMe — SOC Level 1](https://tryhackme.com/path/outline/soclevel1)** — Structured hands-on path
- **[Blue Team Labs Online](https://blueteamlabs.online)** — Real investigation scenarios
- **[Splunk Free](https://www.splunk.com/en_us/download.html)** — Install locally, ingest real logs, write SPL
- **[Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel)** — Free tier on Azure, write KQL queries
- **[Wazuh + Docker](https://documentation.wazuh.com/current/deployment-options/docker/index.html)** — Deploy a real SIEM in minutes
- **[Elastic SIEM](https://www.elastic.co/security)** — Free and excellent documentation

---

## Contributing

Contributions are welcome — especially from other SOC learners who want to add features or improve the realism of detections.

```bash
# Fork the repo, then:
git clone https://github.com/YOUR_USERNAME/rakshak-soc.git
cd rakshak-soc
git checkout -b feature/your-feature-name

# Make your changes, then:
git commit -m "feat: describe what you added"
git push origin feature/your-feature-name

# Open a Pull Request on GitHub
```

### What to contribute

- New event types and MITRE mappings
- Additional correlation rules
- Improved sample log scenarios
- Accessibility improvements
- New chart types or visualizations
- Sigma rule parser
- Real threat intel feed integrations

---

## Security Notice

This project uses a **client-side password gate for demo purposes only.**
The password (`jimil`) is visible in the source code. This is intentional for a portfolio/learning project.

https://rakshak-soc.vercel.app/

**Do not use this authentication mechanism to protect real sensitive data.**
For production use, replace with proper server-side authentication.

---

## License

```
MIT License

Copyright (c) 2025 Rakshak SOC Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software, to deal in the Software without restriction — including
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies — subject to the condition that the above copyright notice and
this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
```

---

## Acknowledgements

- [MITRE ATT&CK Framework](https://attack.mitre.org/) — the industry standard for adversary behavior mapping
- [Syne](https://fonts.google.com/specimen/Syne) · [DM Sans](https://fonts.google.com/specimen/DM+Sans) · [JetBrains Mono](https://www.jetbrains.com/lp/mono/) — typefaces used in the UI
- Every SOC analyst whose blog post, talk, or tweet explained how this work actually happens

---

<div align="center">

<br />

**Built by a learner, for learners.**

If this project helped you understand SOC work better, consider leaving a ⭐

<br />

[![GitHub stars](https://img.shields.io/github/stars/YOUR_USERNAME/rakshak-soc?style=social)](https://github.com/YOUR_USERNAME/rakshak-soc)
&nbsp;
[![GitHub forks](https://img.shields.io/github/forks/YOUR_USERNAME/rakshak-soc?style=social)](https://github.com/YOUR_USERNAME/rakshak-soc/fork)
&nbsp;
[![Follow](https://img.shields.io/github/followers/YOUR_USERNAME?style=social)](https://github.com/YOUR_USERNAME)

<br />

*रक्षक · Guardian · Protector*

</div>
