#!/usr/bin/env python3
"""WebRecox — js_extract.py
Fetch a target page and dump every <script src> URL (absolute).
Usage: python3 js_extract.py https://example.com
"""
import sys, re, argparse, requests
from urllib.parse import urljoin

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    args = ap.parse_args()
    r = requests.get(args.url, headers={"User-Agent":"WebRecox/15"}, timeout=20, verify=False)
    out = set()
    for m in re.finditer(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', r.text, re.I):
        out.add(urljoin(args.url, m.group(1)))
    for m in re.finditer(r'<link[^>]+rel=["\'](?:preload|modulepreload)["\'][^>]+href\s*=\s*["\']([^"\']+\.js[^"\']*)', r.text, re.I):
        out.add(urljoin(args.url, m.group(1)))
    for u in sorted(out): print(u)
    print(f"[+] {len(out)} JS URLs", file=sys.stderr)

if __name__ == "__main__":
    import urllib3; urllib3.disable_warnings(); main()
