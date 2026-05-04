#!/usr/bin/env python3
"""WebRecox — endpoint_extract.py
Pull historical URLs from Wayback CDX + AlienVault OTX for a target domain.
Usage: python3 endpoint_extract.py example.com [--filter api]
"""
import sys, argparse, requests, json
UA = {"User-Agent":"WebRecox/15"}

def wayback(d, limit):
    try:
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{d}/*&output=text&fl=original&collapse=urlkey&limit={limit}"
        return requests.get(url, headers=UA, timeout=60).text.splitlines()
    except Exception as e: print(f"[wayback] {e}", file=sys.stderr); return []

def otx(d):
    out = []
    for path in ["/url_list?limit=500", "/url_list?limit=500&page=2"]:
        try:
            r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{d}{path}", headers=UA, timeout=20)
            j = r.json()
            for u in j.get("url_list", []) or j.get("results", []):
                if isinstance(u, dict) and u.get("url"): out.append(u["url"])
        except Exception as e: print(f"[otx] {e}", file=sys.stderr)
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("domain")
    ap.add_argument("--limit", type=int, default=100000)
    ap.add_argument("--filter", help="substring filter")
    args = ap.parse_args()
    urls = set(wayback(args.domain, args.limit)) | set(otx(args.domain))
    if args.filter: urls = {u for u in urls if args.filter in u}
    for u in sorted(urls): print(u)
    print(f"[+] {len(urls)} unique endpoints", file=sys.stderr)

if __name__ == "__main__": main()
