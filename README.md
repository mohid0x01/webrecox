# ☣ WebRecox — TeamCyberOps Recon Engine v15

> **Browser-based OSINT & Bug-Bounty Recon Platform**
> React 18 · TypeScript · Vite · Cloud-Backed · 50+ OSINT sources · 170+ Oneliners · **NO LIMITS**

![banner](https://github.com/user-attachments/assets/f94d873f-ebb9-43be-8a49-8522ac82d0ad)

**By [@mohidqx](https://github.com/mohidqx) · [TeamCyberOps](https://teamcyberops.vercel.app)**

[![CI](https://github.com/mohidqx/TeamCyberOps-Recon/actions/workflows/ci.yml/badge.svg)](https://github.com/mohidqx/TeamCyberOps-Recon/actions)
![License](https://img.shields.io/badge/license-MIT-amber)
![Stack](https://img.shields.io/badge/stack-React%2018%20%C2%B7%20Vite%205%20%C2%B7%20TS-orange)

---

## ⚡ Quick Start

```bash
git clone https://github.com/mohidqx/TeamCyberOps-Recon.git
cd TeamCyberOps-Recon
npm install --legacy-peer-deps
npm run dev
```

Open `http://localhost:5173`, enter a target domain (e.g. `tesla.com`), and press **`Ctrl + Enter`** to launch a scan.

> ✅ **Authorised security testing only.** Always have written permission before scanning any target.

---

## 🌟 What's new in v15

- 🆕 **WebRecox** rebrand
- 🧬 **JS Code Analyzer** — paste/upload JS to extract endpoints + classify bugs Critical / High / Medium / Low
- 🗺 **Interactive Threat Map** powered by Leaflet.js + CartoDB
- 📊 Animated **Risk Score gauge** with 12-point breakdown
- 🔥 **Unlimited Heatmap** — every subdomain rendered with HSL gradient
- 🔗 **Shareable scan links** + cloud-backed cache prompts
- ⌨ **Keyboard shortcuts** — `Ctrl+Enter`, `Ctrl+E`, `1-9`
- 📜 **170+ Oneliners** — favorites, severity-aware tag filters, CSV export, deep-link to scanner module
- 🚀 Vercel deployment fixed (`--legacy-peer-deps`)

See [**CHANGELOG.md**](./CHANGELOG.md) for the full history.

---

## 🗂 Feature Index

| Category | Features |
|----------|----------|
| 🔍 Subdomains | crt.sh, HackerTarget, AnubisDB, RapidDNS, CertSpotter, OTX, URLScan, ThreatMiner, Sonar, Wayback, BufferOver, ThreatCrowd, VirusTotal, DNSRepo, Riddler, **subdomainfinder.c99.nl**, HudsonRock, Digitorus, DNS Bruteforce (500+ words), Permutations |
| 🌐 Endpoints | Wayback CDX, OTX URLs, CommonCrawl, URLScan, Sitemap, robots.txt, GitHub leaks |
| 🔐 JS & Secrets | 35+ secret patterns, DOM XSS sinks, **JS Code Analyzer**, JWT issues |
| 🛡️ Vulnerabilities | CORS, IDOR, Race, Cache Poison, CRLF, Host Header Injection, Subdomain Takeover (29 fingerprints), Broken Link Hijack, Dependency Confusion, GraphQL introspection, HTTP method abuse, Nuclei templates (30+), Content Discovery (200+ paths), SSTI/SQLi/LFI |
| 🧠 Intelligence | OTX, URLScan history, GitHub code leaks, ASN/BGP, Email security (SPF/DMARC/DKIM/MTA-STS/BIMI), Bug bounty detector, Dark Web OSINT, Breach DBs, Pastes, Exploit-DB, Google Dorks |
| 🗺 Map | Leaflet.js dark threat map with colour-coded markers |
| 📊 Reports | JSON · CSV · TXT · PDF · Burp XML · Nuclei list · Shareable URL · Diff · Risk Score |
| ⚡ Oneliners | 170+ commands — favourites, tags, deep-links into scanner |

---

## ⌨ Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl + Enter` | Start scan |
| `Ctrl + E` | Export JSON |
| `1-9` | Switch tabs within active category |

---

## 🏗 Tech Stack

- **Frontend**: React 18 + TypeScript + Vite 5
- **Styling**: Tailwind CSS v3 (dark / amber design system, semantic HSL tokens)
- **Backend**: Lovable Cloud (Supabase) — scan persistence + share links
- **Maps**: Leaflet.js with CartoDB Dark tiles
- **Audio**: Web Audio API
- **State**: React hooks + React Query
- **UI**: shadcn/ui + Radix primitives

---

## 📦 Project Structure

```
src/
├── pages/
│   ├── Index.tsx          # Main recon dashboard (51 tabs)
│   └── Oneliners.tsx      # Oneliners library + JS Analyzer modal
├── components/
│   ├── ThreatMap.tsx      # Leaflet.js interactive map
│   └── FloatingPortfolio.tsx
├── lib/
│   ├── reconEngine.ts     # Full scanning engine (2700+ lines)
│   ├── exportUtils.ts     # JSON / CSV / TXT / PDF / Burp XML / Nuclei
│   └── soundUtils.ts      # Web Audio API
├── data/
│   └── onelinersData.ts   # 170+ commands + module mapping
└── index.css              # Design tokens
```

---

## 🚀 Deploy on Vercel

This repo ships with [`vercel.json`](./vercel.json) — just import the repo on Vercel, no extra config needed.

```json
{
  "buildCommand": "npm install --legacy-peer-deps && npm run build",
  "installCommand": "npm install --legacy-peer-deps",
  "framework": "vite",
  "rewrites": [{ "source": "/(.*)", "destination": "/index.html" }]
}
```

---

## 🔒 Security & Ethics

- **Authorisation**: scan only targets you have explicit written permission to test
- **Rate-limiting**: built-in delays between requests
- **Client-side**: scanning runs in the browser via fetch + a rotating CORS proxy
- **Cloud cache**: results saved for sharing/diffing only
- **Responsible disclosure**: please follow coordinated disclosure practices

See [SECURITY.md](./SECURITY.md) for vulnerability reporting.

---

## 🤝 Contributing

PRs are welcome — see [CONTRIBUTING.md](./CONTRIBUTING.md) for the workflow, plus how to add new OSINT sources / vuln modules.

---

## 📄 License

[MIT](./LICENSE) — © 2025-2026 TeamCyberOps / @mohidqx

---

## 🔗 Links

- 🌐 Portfolio — [teamcyberops.vercel.app](https://teamcyberops.vercel.app)
- 🐙 GitHub — [@mohidqx](https://github.com/mohidqx)
- 📜 Oneliners — built-in at `/oneliners`

<div align="center">

**WebRecox** · For authorised penetration testing only · `github.com/mohidqx`

</div>
