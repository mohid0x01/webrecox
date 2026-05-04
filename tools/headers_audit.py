#!/usr/bin/env python3
"""WebRecox — headers_audit.py
Score the security headers of a URL.
Usage: python3 headers_audit.py https://example.com
"""
import sys, argparse, requests, urllib3
urllib3.disable_warnings()

CHECKS = [
    ("Strict-Transport-Security", "HSTS", 15),
    ("Content-Security-Policy",   "CSP",  20),
    ("X-Frame-Options",           "XFO",  10),
    ("X-Content-Type-Options",    "XCTO", 10),
    ("Referrer-Policy",           "Referrer", 10),
    ("Permissions-Policy",        "Permissions", 10),
    ("Cross-Origin-Opener-Policy","COOP", 5),
    ("Cross-Origin-Resource-Policy","CORP", 5),
    ("Cross-Origin-Embedder-Policy","COEP", 5),
    ("X-XSS-Protection",          "XXP",  5),
    ("Cache-Control",             "Cache",5),
]

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("url"); args = ap.parse_args()
    r = requests.get(args.url, headers={"User-Agent":"WebRecox/15"}, timeout=15, verify=False)
    score = 0; total = sum(w for _, _, w in CHECKS)
    for h, label, w in CHECKS:
        v = r.headers.get(h)
        mark = "✓" if v else "✗"
        if v: score += w
        print(f"  [{mark}] {label:14} {h:34} {v[:80] if v else '(missing)'}")
    pct = round(score/total*100)
    grade = "A" if pct>=90 else "B" if pct>=75 else "C" if pct>=60 else "D" if pct>=40 else "F"
    print(f"\n[+] Score: {score}/{total} ({pct}%) — Grade {grade}")

if __name__ == "__main__": main()
