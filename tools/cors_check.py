#!/usr/bin/env python3
"""WebRecox — cors_check.py
Test for reflective Origin / wildcard / null-origin CORS misconfig.
Usage: python3 cors_check.py https://example.com/api/foo
"""
import sys, argparse, requests, urllib3
urllib3.disable_warnings()

ORIGINS = [
    "https://evil.com", "null", "https://attacker.example.com",
    "https://example.com.evil.com", "http://example.com",
]

def probe(url, origin):
    try:
        r = requests.get(url, headers={"Origin": origin, "User-Agent":"WebRecox/15"}, timeout=10, verify=False)
        ao = r.headers.get("Access-Control-Allow-Origin"); ac = r.headers.get("Access-Control-Allow-Credentials","")
        return r.status_code, ao, ac
    except Exception as e: return 0, f"ERR: {e}", ""

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("url"); args = ap.parse_args()
    print(f"[+] CORS probe — {args.url}")
    for o in ORIGINS:
        status, ao, ac = probe(args.url, o)
        flag = ""
        if ao == o:                     flag = "🔥 REFLECTIVE"
        elif ao == "*" and ac == "true":flag = "💥 WILDCARD + CREDS"
        elif ao == "null":              flag = "⚠ null origin allowed"
        elif ao == "*":                 flag = "ℹ wildcard"
        print(f"  [{status}] Origin={o:38} → ACAO={ao or '-':38} ACAC={ac or '-':5} {flag}")

if __name__ == "__main__": main()
