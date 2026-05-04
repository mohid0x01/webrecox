#!/usr/bin/env python3
"""WebRecox — nuclei_targets.py
Take a newline-separated subdomain list (file or stdin) and emit a clean
nuclei target file (https:// prefixed, dedup, lowercase, valid hostname).
Usage: python3 nuclei_targets.py subs.txt > targets.txt
       cat subs.txt | python3 nuclei_targets.py -
"""
import sys, re, argparse

HOST = re.compile(r"^[a-z0-9._-]+\.[a-z]{2,}$")

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("file"); args = ap.parse_args()
    src = sys.stdin if args.file == "-" else open(args.file)
    seen = set()
    for line in src:
        h = line.strip().lower().lstrip("*.").split("/")[0]
        if not h or not HOST.match(h) or h in seen: continue
        seen.add(h); print(f"https://{h}")
    print(f"[+] {len(seen)} targets", file=sys.stderr)

if __name__ == "__main__": main()
