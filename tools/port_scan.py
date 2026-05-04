#!/usr/bin/env python3
"""WebRecox — port_scan.py
Threaded TCP connect scan. No raw sockets needed.
Usage: python3 port_scan.py 1.2.3.4 --top-ports 1000
       python3 port_scan.py example.com --ports 80,443,8080,8443
"""
import sys, socket, argparse, concurrent.futures, time

TOP_1000 = sorted(set([
    21,22,23,25,53,80,81,110,111,135,139,143,443,445,465,587,
    993,995,1433,1521,1723,2049,2082,2083,2086,2087,2375,2376,
    3000,3306,3389,4040,4444,5000,5432,5601,5900,5985,5986,
    6379,7000,7001,7002,7474,8000,8008,8009,8010,8080,8081,
    8088,8090,8443,8500,8888,9000,9001,9042,9090,9091,9092,
    9200,9300,9418,9999,10000,11211,15672,27017,28015,50070,
]))

def scan_port(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout): return port
    except Exception: return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--ports", help="comma-separated port list")
    ap.add_argument("--top-ports", type=int, default=0, help="scan first N ports from top-1000")
    ap.add_argument("-t", "--threads", type=int, default=200)
    ap.add_argument("--timeout", type=float, default=1.5)
    args = ap.parse_args()
    if args.ports:
        ports = [int(p) for p in args.ports.split(",") if p.strip()]
    elif args.top_ports:
        ports = TOP_1000[:args.top_ports]
    else:
        ports = TOP_1000
    try: ip = socket.gethostbyname(args.target)
    except Exception: print(f"cannot resolve {args.target}"); sys.exit(1)
    print(f"[+] scanning {ip} — {len(ports)} ports — {args.threads} threads")
    t0 = time.time(); open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        for r in ex.map(lambda p: scan_port(ip, p, args.timeout), ports):
            if r: print(f"  [+] {r}/tcp open"); open_ports.append(r)
    print(f"[+] {len(open_ports)} open ports in {time.time()-t0:.1f}s")

if __name__ == "__main__": main()
