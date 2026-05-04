#!/usr/bin/env python3
"""WebRecox — secret_scan.py
Regex-scan a JS/text file (or stdin) for secrets.
Usage: python3 secret_scan.py path/to/file.js
       cat file.js | python3 secret_scan.py -
"""
import sys, re, argparse

PATTERNS = [
    ("CRITICAL", "AWS Access Key",      r"\bAKIA[0-9A-Z]{16}\b"),
    ("CRITICAL", "Slack Token",         r"\bxox[abprs]-[A-Za-z0-9-]{10,48}\b"),
    ("CRITICAL", "GitHub Token",        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"),
    ("CRITICAL", "Stripe Live",         r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b"),
    ("CRITICAL", "Private Key",         r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE KEY-----"),
    ("HIGH",     "Google API Key",      r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    ("HIGH",     "Bearer Token",        r"Bearer\s+[A-Za-z0-9\-_=.+/]{30,}"),
    ("HIGH",     "Generic API Key",     r"(?:api[_-]?key|apikey|api_secret|access[_-]?token)\s*[:=]\s*[\"']([A-Za-z0-9_\-]{20,})[\"']"),
    ("HIGH",     "Mailgun",             r"\bkey-[0-9a-zA-Z]{32}\b"),
    ("MEDIUM",   "JWT",                 r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    ("MEDIUM",   "Stripe Test",         r"\b(?:sk|pk)_test_[0-9a-zA-Z]{20,}\b"),
    ("MEDIUM",   "Firebase URL",        r"https?://[a-z0-9-]+\.firebaseio\.com"),
]

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("file"); args = ap.parse_args()
    txt = sys.stdin.read() if args.file == "-" else open(args.file, errors="ignore").read()
    n = 0
    for sev, name, pat in PATTERNS:
        for m in re.finditer(pat, txt):
            line = txt.count("\n", 0, m.start()) + 1
            val = (m.group(1) if m.groups() else m.group(0))[:120]
            print(f"  [{sev:8}] {name:24} L{line:5}  {val}")
            n += 1
    print(f"\n[+] {n} potential secret(s) found")

if __name__ == "__main__": main()
