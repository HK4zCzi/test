#!/usr/bin/env python3
"""
Test toàn bộ scanner với youtube.com
Chạy: python3 test_scanners.py
"""
import sys, os, json, time, warnings

# Suppress SSL warnings — not relevant for scanner testing
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Dùng API keys từ env hoặc set thẳng để test local
os.environ.setdefault("VT_API_KEY",      os.getenv("VT_API_KEY", ""))
os.environ.setdefault("SHODAN_API_KEY",  os.getenv("SHODAN_API_KEY", ""))
os.environ.setdefault("URLSCAN_API_KEY", os.getenv("URLSCAN_API_KEY", ""))

TARGET_DOMAIN  = "cmc.com.vn"
TARGET_IP      = "8.8.8.8"
TARGET_IP_PRIV = "127.0.0.1"

G  = "\033[92m"; R = "\033[91m"; Y = "\033[93m"
B  = "\033[94m"; E = "\033[0m";  BOLD = "\033[1m"

results = []

def run(name, fn, *args):
    print(f"\n{B}{BOLD}{'='*55}{E}")
    print(f"{B}{BOLD}  {name}{E}")
    print(f"{B}{'='*55}{E}")
    t = time.time()
    try:
        r = fn(*args)
        elapsed = round(time.time() - t, 2)
        if r and isinstance(r, list) and r[0]:
            for k, v in r[0].items():
                if k == "created_at": continue
                s = json.dumps(v, ensure_ascii=False) if not isinstance(v, str) else v
                print(f"  {Y}{k:25}{E} {s[:130]}{'...' if len(s)>130 else ''}")
            print(f"\n  {G}✅ PASSED{E} ({elapsed}s)")
            results.append((name, "PASS", elapsed, ""))
        else:
            print(f"  {R}❌ EMPTY RESULT{E}")
            results.append((name, "EMPTY", elapsed, "empty"))
    except Exception as e:
        elapsed = round(time.time() - t, 2)
        print(f"  {R}❌ FAILED: {e}{E}")
        results.append((name, "FAIL", elapsed, str(e)[:120]))

# ── Tests ──────────────────────────────────────────────────────────
from app.scanner.dns_scanner import DNSScanner
run("DNS Scanner", lambda: DNSScanner().scan(TARGET_DOMAIN))

from app.scanner.whois_scanner import WHOISScanner
run("WHOIS Scanner", lambda: WHOISScanner().scan(TARGET_DOMAIN))

from app.scanner.subdomain_scanner import SubdomainScanner
run("Subdomain Scanner", lambda: SubdomainScanner().scan(TARGET_DOMAIN))

from app.scanner.cert_trans_scanner import CertTransScanner
run("Cert Transparency (crt.sh)", lambda: CertTransScanner().scan(TARGET_DOMAIN))

from app.scanner.ssl_scanner import SSLScanner
run("SSL Scanner", lambda: SSLScanner().scan(TARGET_DOMAIN))

from app.scanner.headers_scanner import HeadersScanner
run("Security Headers", lambda: HeadersScanner().scan(TARGET_DOMAIN))

from app.scanner.waf_scanner import WAFScanner
run("WAF Detection (wafw00f)", lambda: WAFScanner().scan(TARGET_DOMAIN))

from app.scanner.tech_scanner import TechScanner
run("Technology Detection", lambda: TechScanner().scan(TARGET_DOMAIN))

from app.scanner.http_probe_scanner import HTTPProbeScanner
run("HTTP Probe", lambda: HTTPProbeScanner().scan(TARGET_DOMAIN))

from app.scanner.ip_scanner import IPScanner
run(f"IP Geolocation ({TARGET_IP})", lambda: IPScanner().scan(TARGET_IP))

from app.scanner.port_scanner import PortScanner
run(f"Port Scanner ({TARGET_IP_PRIV})", lambda: PortScanner().scan(TARGET_IP_PRIV))

from app.scanner.takeover_scanner import TakeoverScanner
run("Subdomain Takeover", lambda: TakeoverScanner().scan(TARGET_DOMAIN))

from app.scanner.gau_scanner import GAUScanner
run("GetAllURLs / Wayback", lambda: GAUScanner().scan(TARGET_DOMAIN))

from app.scanner.shodan_scanner import ShodanScanner
run("Shodan", lambda: ShodanScanner().scan(TARGET_DOMAIN))

from app.scanner.virustotal_scanner import VirusTotalScanner
run("VirusTotal + OTX", lambda: VirusTotalScanner().scan(TARGET_DOMAIN))

from app.scanner.urlscan_scanner import URLScanScanner
run("URLScan.io", lambda: URLScanScanner().scan(TARGET_DOMAIN))

from app.scanner.cors_scanner import CORSScanner
run("CORS Misconfiguration", lambda: CORSScanner().scan(TARGET_DOMAIN))

from app.scanner.s3_scanner import S3Scanner
run("S3 Bucket Enum", lambda: S3Scanner().scan(TARGET_DOMAIN))

from app.scanner.js_scanner import JSScanner
run("JS Files / Secrets", lambda: JSScanner().scan(TARGET_DOMAIN))

from app.scanner.dir_scanner import DirScanner
run("Directory Brute Force", lambda: DirScanner().scan(TARGET_DOMAIN))

# ── Summary ────────────────────────────────────────────────────────
print(f"\n\n{BOLD}{'='*60}{E}")
print(f"{BOLD}  SCANNER TEST SUMMARY — {TARGET_DOMAIN}{E}")
print(f"{BOLD}{'='*60}{E}")

passed = [r for r in results if r[1] == "PASS"]
failed = [r for r in results if r[1] == "FAIL"]
empty  = [r for r in results if r[1] == "EMPTY"]

for name, status, elapsed, err in results:
    icon  = "✅" if status == "PASS" else ("⚠️ " if status == "EMPTY" else "❌")
    color = G if status == "PASS" else (Y if status == "EMPTY" else R)
    err_s = f"  → {err}" if err else ""
    print(f"  {icon} {color}{name:42}{E} {elapsed:5.1f}s{err_s}")

print(f"\n  Total: {len(results)} | {G}Pass: {len(passed)}{E} | {Y}Empty: {len(empty)}{E} | {R}Fail: {len(failed)}{E}")
print(f"{BOLD}{'='*60}{E}\n")
