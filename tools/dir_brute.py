#!/usr/bin/env python3
"""WebRecox — dir_brute.py
Lightweight directory/file bruteforcer.
Usage: python3 dir_brute.py https://example.com -w wordlist.txt
"""
import sys, argparse, concurrent.futures, requests, urllib3
urllib3.disable_warnings()
SEED_WORDS = ["admin","login","api","backup","config","robots.txt","sitemap.xml",
    ".git/config",".env","wp-admin","phpmyadmin","dashboard","old","test","dev",
    "uploads","files","static","assets","internal","private","debug","status",
    "actuator/health","metrics","graphql","swagger","docs","api/v1","api/v2"]

def probe(base, word, timeout, ua):
    url = base.rstrip("/") + "/" + word.lstrip("/")
    try:
        r = requests.get(url, headers={"User-Agent": ua}, timeout=timeout, verify=False, allow_redirects=False)
        if r.status_code < 400 or r.status_code in (401, 403):
            return r.status_code, len(r.content), url
    except Exception: pass
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="https://example.com")
    ap.add_argument("-w", "--wordlist")
    ap.add_argument("-t", "--threads", type=int, default=40)
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--ua", default="WebRecox/15")
    args = ap.parse_args()
    words = open(args.wordlist).read().splitlines() if args.wordlist else SEED_WORDS
    words = [w.strip() for w in words if w.strip() and not w.startswith("#")]
    print(f"[+] bruting {args.target} with {len(words)} words / {args.threads} threads")
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        for r in ex.map(lambda w: probe(args.target, w, args.timeout, args.ua), words):
            if r: print(f"  [{r[0]}] {r[2]}  ({r[1]} bytes)")

if __name__ == "__main__": main()
