#!/usr/bin/env python3
"""WebRecox — subfind.py
Aggregate subdomains from public passive sources: crt.sh, AnubisDB, HackerTarget, ThreatCrowd.
Usage: python3 subfind.py example.com [--out subs.txt]
"""
import sys, argparse, json, re
import requests

UA = {"User-Agent": "WebRecox/15"}

def crtsh(d):
    out = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{d}&output=json", headers=UA, timeout=30)
        for row in r.json():
            for n in str(row.get("name_value", "")).splitlines():
                n = n.strip().lower().lstrip("*.")
                if n.endswith(d): out.add(n)
    except Exception as e: print(f"[crt.sh] {e}", file=sys.stderr)
    return out

def anubis(d):
    try:
        r = requests.get(f"https://jldc.me/anubis/subdomains/{d}", headers=UA, timeout=15)
        return {x.strip().lower() for x in r.json() if isinstance(x, str) and x.endswith(d)}
    except Exception as e: print(f"[anubis] {e}", file=sys.stderr); return set()

def hackertarget(d):
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={d}", headers=UA, timeout=15)
        out = set()
        for line in r.text.splitlines():
            host = line.split(",")[0].strip().lower()
            if host.endswith(d): out.add(host)
        return out
    except Exception as e: print(f"[hackertarget] {e}", file=sys.stderr); return set()

def threatcrowd(d):
    try:
        r = requests.get(f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={d}", headers=UA, timeout=15)
        return {x.strip().lower() for x in r.json().get("subdomains", []) if x.endswith(d)}
    except Exception as e: print(f"[threatcrowd] {e}", file=sys.stderr); return set()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("domain")
    ap.add_argument("--out", help="write to file")
    args = ap.parse_args()
    d = args.domain.lower().strip()
    subs = crtsh(d) | anubis(d) | hackertarget(d) | threatcrowd(d)
    subs = sorted(subs)
    print(f"[+] {len(subs)} unique subdomains", file=sys.stderr)
    text = "\n".join(subs)
    if args.out:
        open(args.out, "w").write(text + "\n")
        print(f"[+] wrote {args.out}", file=sys.stderr)
    else:
        print(text)

if __name__ == "__main__": main()
