# Changelog

All notable changes to **WebRecox** (TeamCyberOps Recon Engine) are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org).

## [15.1.0] — 2026-05-04

### Added
- ⚙ **Configurable proxy fallback** (`src/lib/proxyConfig.ts` + `ProxySettingsPanel.tsx`) — enable/disable, timeout slider (3–45s), reorderable provider list (AllOrigins, corsproxy.io, codetabs, thingproxy, cors-anywhere). Persisted in localStorage.
- 🎯 **Profile selector wired** (`src/lib/scanProfiles.ts`) — Quick / Deep / Stealth now actually toggle module count, concurrency, timeout multiplier, and stealth jitter.
- 🧬 **Endpoint extractor — major upgrade**: AST walk **plus** regex fallback for concatenated/minified URLs, **plus** `crawlAndAnalyze()` that fetches every `<script src>` from a target and analyzes each.
- 🔬 **JS Analyzer modal** with three input modes: paste code, multi-file upload, or **crawl target URL**. Severity filter chips, file/line attribution, confidence badges.
- 🚀 **JS Analyzer button in hero** beside Full Scan, plus a compact button in the top nav.
- 🖱 **Hover actions on JS rows** — every JS file in the JS tab reveals an "Analyze" button on hover that opens the analyzer pre-loaded with that URL.
- 🔒 **Secret-gated History tab** — locked by default; passphrase `WebRecox-TeamCyberOps` unlocks. Re-lock from inside the tab.
- 🐍 **Real Python `tools/` directory** — 11 self-contained, runnable scripts mapped to oneliner categories (`subfind.py`, `dns_resolve.py`, `port_scan.py`, `dir_brute.py`, `js_extract.py`, `endpoint_extract.py`, `tech_detect.py`, `headers_audit.py`, `secret_scan.py`, `cors_check.py`, `nuclei_targets.py`) plus README and requirements.

### Changed
- `pFetch` and `sf` in `reconEngine.ts` now consume runtime proxy config instead of a hard-coded list.
- `runFullScan` receives a profile-filtered source map via `applyProfileToSources()`.

## [15.0.0] — 2026-05-02

### Added
- 🆕 **WebRecox** branding across hero, header, and meta tags.
- 🧬 **JS Code Analyzer** — paste or upload JS to extract real endpoints and classify bugs as Critical / High / Medium / Low. Detects DOM XSS sinks, hardcoded secrets, dangerous patterns (`eval`, `innerHTML`, `document.write`, `dangerouslySetInnerHTML`), debug flags, exposed source maps and more.
- 🗺 **Interactive Threat Map** (Leaflet.js + CartoDB Dark) with color-coded IP markers.
- 📊 **Animated Risk Score gauge** with 12-point breakdown by category.
- 🔥 **Unlimited Heatmap** — every subdomain rendered with HSL gradient by composite risk.
- 🔗 **Shareable scan links** (`?share=<id>`) — recipients load cached results instantly.
- ⌨ **Keyboard shortcuts** — `Ctrl+Enter` scan · `Ctrl+E` export · `1-9` tab switch.
- ☁ **Cloud-backed persistence** — automatic dedupe & "Resume cached scan" prompt.
- 🛡 **New vuln modules** — IDOR, Race, Cache Poison, CRLF, Host Header Injection, Broken Link Hijack, Dependency Confusion, GraphQL introspection, HTTP method abuse, Exploit-DB lookups.
- 🧠 **Tech detection** expanded to ~140 fingerprints incl. meta-generators and probe endpoints.
- 🗝 **35+ secret patterns** (AWS, GCP, GitHub, Stripe, OpenAI, Anthropic, Discord, Slack…).
- 📜 **170+ Oneliners** with module-deep-link, severity tags, favorites, copy + CSV export.
- 🎵 **Premium audio feedback** via Web Audio API.
- 🎨 **Floating TeamCyberOps Portfolio** widget with quick links.
- 📂 **Production scaffolding** — `LICENSE`, `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, GitHub Actions CI, issue & PR templates, `vercel.json`.

### Changed
- 🚫 **All result limits removed.** Wayback / CommonCrawl / OTX fetches raised to 1M+; UI rendering up to 100M+ rows.
- 🎯 Tabs reorganized to follow scan execution sequence.
- 🎨 Oneliners page restyled to match the dark / amber Recon theme.
- ⚡ Vercel build now uses `npm install --legacy-peer-deps` to resolve React 18/19 peer conflict.

### Fixed
- ⚙ Vercel deployment failure caused by `react-leaflet` peer-dep mismatch.
- 🔄 Heatmap previously truncating at 100 entries.

## [14.6.0] — 2026-04-20

### Added
- Initial public release of the v14.6 recon dashboard, 17+ subdomain sources, Nuclei templates, content discovery and CORS scanner.

[Unreleased]: https://github.com/mohidqx/TeamCyberOps-Recon/compare/v15.0.0...HEAD
[15.0.0]: https://github.com/mohidqx/TeamCyberOps-Recon/releases/tag/v15.0.0
[14.6.0]: https://github.com/mohidqx/TeamCyberOps-Recon/releases/tag/v14.6.0
