# WebRecox — Tools Directory

Real, runnable Python utilities mapped to the categories used by the WebRecox Oneliners page.
Each script is self-contained — only `requests` is required for HTTP-based tools (`pip install requests`).

| Script | Category | Purpose |
|--------|----------|---------|
| `subfind.py`     | subdomain        | Aggregate subdomains from crt.sh, AnubisDB, HackerTarget, ThreatCrowd |
| `dns_resolve.py` | dns              | Resolve A/AAAA/MX/TXT/NS/CNAME for a host or list |
| `port_scan.py`   | port             | Threaded TCP connect-scan over the top-1000 / custom ports |
| `dir_brute.py`   | content          | Lightweight dir/file bruteforcer (status filter, recursion off) |
| `js_extract.py`  | js               | Pull every `<script src>` from a target and dump the URLs |
| `endpoint_extract.py` | endpoint    | Wayback + AlienVault OTX URL aggregator with regex filter |
| `tech_detect.py` | tech             | HTTP fingerprinter: server / x-powered-by / generator / cookies |
| `headers_audit.py` | headers        | Score security headers (CSP, HSTS, XFO, etc.) |
| `secret_scan.py` | secrets          | Regex-scan a JS/text file for AWS / GitHub / Stripe / JWT secrets |
| `cors_check.py`  | cors             | Reflective Origin / wildcard / null-origin CORS tester |
| `nuclei_targets.py` | nuclei        | Take a subdomain list and emit a clean nuclei target file |

## Usage

```bash
python3 tools/subfind.py example.com
python3 tools/port_scan.py 1.2.3.4 --top-ports 1000
python3 tools/headers_audit.py https://example.com
python3 tools/secret_scan.py path/to/file.js
```

Run any script with `-h` for full options.

## Install

```bash
pip install -r tools/requirements.txt
```

> These are intentionally minimal. For heavy lifting use the standard tools
> referenced in the Oneliners page (subfinder, ffuf, nuclei, etc).
