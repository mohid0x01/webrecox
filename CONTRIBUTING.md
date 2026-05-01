# Contributing to TeamCyberOps Recon

Thanks for your interest in contributing! This project welcomes pull requests
that add new OSINT sources, scanning modules, UI improvements, or bug fixes.

## Quick start

```bash
git clone https://github.com/mohidqx/TeamCyberOps-Recon.git
cd TeamCyberOps-Recon
npm install
npm run dev
```

## Workflow

1. Fork and create a feature branch: `git checkout -b feature/<short-name>`
2. Make focused commits with clear messages
3. Run `npm run lint` and `npm test` before pushing
4. Open a pull request describing **what** changed and **why**

## Adding a new subdomain source

1. Add an `async` fetch function to `src/lib/reconEngine.ts` that returns
   `{ subdomain, ip, source }[]`.
2. Register it in the `subSources` array inside `runFullScan`.
3. Use `pFetch` (proxy rotation) for any cross-origin request.
4. Always validate output with `isValidSub(host, domain)`.

## Adding a new vulnerability check

1. Add a finding interface to `ScanState`.
2. Add a scanner function that uses strict regex/heuristics to **avoid
   false positives** (this is the hard part — be conservative).
3. Wire it into `runFullScan` behind a `safeRun(...)` guard.
4. Add a tab in `src/pages/Index.tsx` to render the findings.

## Code style

- TypeScript strict mode
- Use the existing semantic Tailwind tokens (`hsl(var(--primary))` etc.)
- No raw color classes (`text-red-500` etc.) — see `src/index.css`
- React hooks only — no class components

## Ethics

Submissions that enable obvious abuse (mass exploitation, unauthorized
intrusions, credential stuffing helpers without authorization) will be
rejected. This tool is for **authorized** security testing only.

## License

By contributing you agree your work is licensed under the MIT License
included in this repository.
