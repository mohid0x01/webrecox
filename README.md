# ☣ TeamCyberOps Recon Engine v14.6

> **Browser-based OSINT & Bug Bounty Recon Platform**
> React + TypeScript · Cloud-Backed · 50+ OSINT Sources · No Limits

![image](https://github.com/user-attachments/assets/f94d873f-ebb9-43be-8a49-8522ac82d0ad)

**By [@mohidqx](https://github.com/mohidqx) · [TeamCyberOps](https://teamcyberops.vercel.app)**

---

## ⚡ Quick Start

```bash
# Clone and install
git clone https://github.com/mohidqx/TeamCyberOps-Recon.git
cd TeamCyberOps-Recon
npm install

# Start development server
npm run dev
```

Open `http://localhost:5173`, enter a target domain (e.g. `tesla.com`), and click **Full Scan** or press `Ctrl + Enter`.

> ✅ **For authorized security testing only.** Always have written permission before scanning any target.

---

## 🗂️ Feature Index

| Category | Features |
|----------|----------|
| 🔍 Subdomains | crt.sh, HackerTarget, AnubisDB, RapidDNS, CertSpotter, OTX PassiveDNS, URLScan, ThreatMiner, Sonar, Wayback, BufferOver, ThreatCrowd, VirusTotal, DNSRepo, Riddler, DNS Bruteforce (500+ words), Permutation Engine |
| 🌐 Endpoints | Wayback CDX, OTX URLs, CommonCrawl, URLScan URLs, Sitemap parse, robots.txt, GitHub Endpoints |
| 🔐 JS & Secrets | 35+ secret patterns, DOM XSS sink detection, JS Code Analyzer (real endpoints, bug detection), JWT Analysis |
| 🛡️ Vulnerabilities | CORS Misconfig, Nuclei Templates (30+), Content Discovery (200+ paths), SSTI/SQLi/LFI, HTTP Methods, Broken Link Hijacking, Dependency Confusion, IDOR, Race Conditions, Cache Poisoning, CRLF Injection, Host Header Injection |
| 🧠 Intelligence | OTX Threat Intel, URLScan History, GitHub Code Leaks, ASN/BGP Recon, Email Security (SPF/DMARC/DKIM/MTA-STS/BIMI), Bug Bounty Detector, Dark Web OSINT, Breach Databases, Paste Sites, Exploit DB, Google Dorks (12 categories) |
| 🗺️ Interactive Map | Leaflet.js threat map with color-coded IP markers, geolocation data, CVE/port overlays |
| 📊 Reports | JSON, CSV, TXT, PDF, Burp Suite XML, Nuclei target list, Shareable URL, Scan Diff, Risk Score |

---

## 🧩 All Tabs

### 🔴 Subdomains (`Subs`)
Aggregates results from 17+ passive sources simultaneously. Each subdomain shows IP, HTTP status, open ports, geolocation, CNAME chain, source badges. Smart filtering, export, and pagination.

### 🟣 DNS
Multi-resolver DNS (Google, Cloudflare, Quad9) for A, AAAA, MX, NS, TXT, CNAME, SOA, CAA records. Deduplication with resolver confirmation.

### 🟣 Ports
Shodan InternetDB (no API key needed) for ports, CVEs, and vulnerabilities per IP. Dangerous ports highlighted.

### 🟢 Endpoints
8 sources, deduplication, type classification (JS, PHP, API, Admin, Config, Auth).

### 🟡 JS Files & JS Code Analyzer
Lists all `.js` files. **JS Code Analyzer** scans for real API endpoints, security bugs (Critical/High/Medium/Low), hardcoded credentials, and dangerous patterns.

### 🔑 Secrets
35+ secret pattern types with strict validation to minimize false positives. AWS, Google, GitHub, Stripe, OpenAI, Anthropic, Discord, Slack, and more.

### 🗺️ Threat Map
Interactive Leaflet.js dark world map with color-coded markers:
- 🔴 Red = CVEs or dangerous ports
- 🟢 Green = CDN edge nodes
- 🟡 Amber = normal hosts

### ⚠️ Vulnerability Scanners
CORS Misconfig, IDOR, Race Conditions, Cache Poisoning, CRLF Injection, Host Header Injection, Subdomain Takeover (29 fingerprints), GraphQL Introspection, HTTP Methods.

### 📊 Risk Score
Composite risk score (0–100) with breakdown by category. Animated gauge visualization.

### 🔥 Heatmap
Risk heatmap of ALL subdomains (no limits) with color-coded blocks.

### 🔗 Shareable Links
Share scan results via URL. Recipients see full results without re-scanning.

### ⌨️ Keyboard Shortcuts
| Shortcut | Action |
|----------|--------|
| `Ctrl + Enter` | Start scan |
| `Ctrl + E` | Export JSON |
| `1-9` | Switch tabs |

---

## 🏗️ Tech Stack

- **Frontend**: React 18 + TypeScript + Vite 5
- **Styling**: Tailwind CSS v3 with custom amber/dark design system
- **Backend**: Lovable Cloud (Supabase) for scan persistence
- **Maps**: Leaflet.js with CartoDB dark tiles
- **Audio**: Web Audio API for scan sound effects
- **State**: React hooks + React Query
- **UI**: shadcn/ui + Radix primitives

---

## 📦 Project Structure

```
src/
├── pages/
│   ├── Index.tsx          # Main recon dashboard (50+ tabs)
│   └── Oneliners.tsx      # Bug bounty command library
├── components/
│   └── ThreatMap.tsx      # Leaflet.js interactive map
├── lib/
│   ├── reconEngine.ts     # Full scanning engine (2400+ lines)
│   ├── exportUtils.ts     # Export (JSON/CSV/TXT/PDF/Burp/Nuclei)
│   └── soundUtils.ts      # Web Audio API sounds
├── data/
│   └── onelinersData.ts   # 100+ bug bounty commands
└── index.css              # Design system tokens
```

---

## 🔒 Security & Ethics

- **Authorization**: Only scan targets you have explicit written permission to test
- **Rate Limiting**: Built-in delays between requests to avoid overwhelming targets
- **No Server**: All scanning happens client-side via browser fetch
- **Data Storage**: Scan results saved to cloud for caching and sharing
- **Responsible Disclosure**: Follow coordinated disclosure practices

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🔗 Links

- **Portfolio**: [teamcyberops.vercel.app](https://teamcyberops.vercel.app)
- **GitHub**: [@mohidqx](https://github.com/mohidqx)
- **Oneliners**: Built-in at `/oneliners` route

---

<div align="center">
  <strong>© 2025 TeamCyberOps — For authorized penetration testing only</strong>
  <br/>
  <a href="https://github.com/mohidqx">github.com/mohidqx</a>
</div>
