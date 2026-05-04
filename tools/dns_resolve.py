#!/usr/bin/env python3
"""WebRecox — dns_resolve.py
Resolve A/AAAA/MX/TXT/NS/CNAME for one host or a list (newline separated).
Usage: python3 dns_resolve.py example.com
       cat hosts.txt | python3 dns_resolve.py -
"""
import sys, socket, argparse

try:
    import dns.resolver
    HAS_DNSPY = True
except ImportError:
    HAS_DNSPY = False

def resolve_basic(host):
    try:
        return [host, socket.gethostbyname(host)]
    except Exception: return [host, ""]

def resolve_full(host):
    out = {"host": host, "A": [], "AAAA": [], "MX": [], "TXT": [], "NS": [], "CNAME": []}
    if not HAS_DNSPY:
        try: out["A"] = [socket.gethostbyname(host)]
        except Exception: pass
        return out
    r = dns.resolver.Resolver()
    r.lifetime = 4
    for rt in out.keys():
        if rt == "host": continue
        try:
            ans = r.resolve(host, rt)
            out[rt] = [str(x).rstrip(".") for x in ans]
        except Exception: pass
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="hostname or '-' for stdin")
    args = ap.parse_args()
    hosts = sys.stdin.read().splitlines() if args.target == "-" else [args.target]
    for h in [x.strip() for x in hosts if x.strip()]:
        rec = resolve_full(h)
        print(f"{rec['host']:40}  A={','.join(rec['A']) or '-'}  CNAME={','.join(rec['CNAME']) or '-'}  MX={len(rec['MX'])}  TXT={len(rec['TXT'])}")

if __name__ == "__main__": main()
