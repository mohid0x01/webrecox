#!/usr/bin/env python3
"""WebRecox — tech_detect.py
HTTP fingerprinter: Server, X-Powered-By, generator, frameworks, cookies.
Usage: python3 tech_detect.py https://example.com
"""
import sys, argparse, re, requests, urllib3
urllib3.disable_warnings()

PATTERNS = {
    "WordPress":   [r"wp-content/", r"wp-includes/", r'<meta name="generator" content="WordPress'],
    "Drupal":      [r"Drupal\.settings", r"sites/all/(?:modules|themes)"],
    "Joomla":      [r"/components/com_", r"Joomla!"],
    "Next.js":     [r"/_next/static/", r"__NEXT_DATA__"],
    "Nuxt":        [r"/_nuxt/", r"window\.__NUXT__"],
    "React":       [r"data-reactroot", r"react-dom"],
    "Vue":         [r"data-v-[0-9a-f]{8}", r"window\.__INITIAL_STATE__"],
    "Angular":     [r"ng-version=", r"ng-app="],
    "Cloudflare":  [r"cf-ray", r"__cf_bm"],
    "AWS CloudFront": [r"x-amz-cf-id"],
    "Akamai":      [r"akamai"],
    "Nginx":       [r"^nginx"],
    "Apache":      [r"^Apache"],
    "Express":     [r"X-Powered-By: Express"],
    "Laravel":     [r"laravel_session", r"XSRF-TOKEN"],
    "Django":      [r"csrftoken", r"sessionid"],
    "Rails":       [r"_session_id", r"X-Runtime"],
}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    args = ap.parse_args()
    r = requests.get(args.url, headers={"User-Agent":"WebRecox/15"}, timeout=15, verify=False)
    body = r.text[:200000]; hdrs = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
    blob = body + "\n" + hdrs
    found = set()
    for tech, pats in PATTERNS.items():
        for p in pats:
            if re.search(p, blob, re.I): found.add(tech); break
    print(f"[+] HTTP {r.status_code} — {args.url}")
    print(f"[+] Server     : {r.headers.get('Server','-')}")
    print(f"[+] Powered-By : {r.headers.get('X-Powered-By','-')}")
    g = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if g: print(f"[+] Generator  : {g.group(1)}")
    print(f"[+] Detected   : {', '.join(sorted(found)) or '-'}")

if __name__ == "__main__": main()
