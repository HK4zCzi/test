#!/usr/bin/env python3
"""
Test compatibility logic + API endpoints
Chạy: python3 test_compatibility.py
(server phải đang chạy ở localhost:8080)
"""
import sys, json, urllib.request, urllib.error

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; E = "\033[0m"; B = "\033[1m"
BASE = "http://localhost:8080"

def req(method, path, body=None):
    url = BASE + path
    data = json.dumps(body).encode() if body else None
    r = urllib.request.Request(url, data=data,
        headers={"Content-Type":"application/json"}, method=method)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())
    except Exception as e:
        return 0, {"error": str(e)}

ok = []; fail = []

def test(name, condition, detail=""):
    if condition:
        print(f"  {G}✅ {name}{E}" + (f" — {detail}" if detail else ""))
        ok.append(name)
    else:
        print(f"  {R}❌ {name}{E}" + (f" — {detail}" if detail else ""))
        fail.append(name)

print(f"\n{B}{'='*60}{E}")
print(f"{B}  Setup: creating test assets{E}")
print(f"{B}{'='*60}{E}")

# Create domain asset
s, r = req("POST", "/assets/single", {"name":"test-domain.example.com","type":"domain"})
domain_id = r.get("id","")
test("Create domain asset", s==201, f"id={domain_id[:8]}...")

# Create IP asset
s, r = req("POST", "/assets/single", {"name":"8.8.8.8","type":"ip"})
ip_id = r.get("id","")
test("Create IP asset", s==201, f"id={ip_id[:8]}...")

# Create service asset
s, r = req("POST", "/assets/single", {"name":"my-service","type":"service"})
svc_id = r.get("id","")
test("Create service asset", s==201, f"id={svc_id[:8]}...")

print(f"\n{B}{'='*60}{E}")
print(f"{B}  Test 1: Domain-only scans on DOMAIN asset (should pass){E}")
print(f"{B}{'='*60}{E}")

for scan_type in ["dns","whois","ssl","tech","headers","waf","subdomain","cert_trans",
                   "gau","virustotal","urlscan","cors","s3","dir_brute","http_probe","takeover","js_scan"]:
    s, r = req("POST", f"/assets/{domain_id}/scan", {"scan_type": scan_type})
    test(f"domain + {scan_type}", s==202, r.get("detail","") if s!=202 else f"job={r.get('id','')[:8]}...")

print(f"\n{B}{'='*60}{E}")
print(f"{B}  Test 2: IP-only scans on IP asset (should pass){E}")
print(f"{B}{'='*60}{E}")

for scan_type in ["ip","asn","reverse_dns","shodan","port"]:
    s, r = req("POST", f"/assets/{ip_id}/scan", {"scan_type": scan_type})
    test(f"ip + {scan_type}", s==202, r.get("detail","") if s!=202 else f"job={r.get('id','')[:8]}...")

print(f"\n{B}{'='*60}{E}")
print(f"{B}  Test 3: IP scans on DOMAIN asset (should FAIL with 400){E}")
print(f"{B}{'='*60}{E}")

for scan_type in ["ip","asn","shodan","port"]:
    s, r = req("POST", f"/assets/{domain_id}/scan", {"scan_type": scan_type})
    test(f"domain + {scan_type} → 400", s==400, r.get("detail",""))

print(f"\n{B}{'='*60}{E}")
print(f"{B}  Test 4: Domain scans on IP asset (should FAIL with 400){E}")
print(f"{B}{'='*60}{E}")

for scan_type in ["dns","whois","ssl","cors","dir_brute"]:
    s, r = req("POST", f"/assets/{ip_id}/scan", {"scan_type": scan_type})
    test(f"ip + {scan_type} → 400", s==400, r.get("detail",""))

print(f"\n{B}{'='*60}{E}")
print(f"{B}  Test 5: Scan GROUPS (should auto-select correct scans){E}")
print(f"{B}{'='*60}{E}")

s, r = req("POST", f"/assets/{domain_id}/scan", {"scan_type": "domain_full"})
test("domain + domain_full group", s==202 and r.get("jobs_started",0)>0,
     f"started {r.get('jobs_started',0)} jobs" if s==202 else r.get("detail",""))

s, r = req("POST", f"/assets/{ip_id}/scan", {"scan_type": "ip_full"})
test("ip + ip_full group", s==202 and r.get("jobs_started",0)>0,
     f"started {r.get('jobs_started',0)} jobs" if s==202 else r.get("detail",""))

s, r = req("POST", f"/assets/{domain_id}/scan", {"scan_type": "ip_full"})
test("domain + ip_full → 400 (no domain scans in ip_full)", s==400, r.get("detail",""))

s, r = req("POST", f"/assets/{ip_id}/scan", {"scan_type": "domain_full"})
test("ip + domain_full → 400 (no ip scans in domain_full)", s==400, r.get("detail",""))

s, r = req("POST", f"/assets/{domain_id}/scan", {"scan_type": "all"})
test("domain + all group", s==202, f"started {r.get('jobs_started',0)} jobs" if s==202 else r.get("detail",""))

s, r = req("POST", f"/assets/${ip_id}/scan", {"scan_type": "all"})
test("ip + all group", s==202, f"started {r.get('jobs_started',0)} jobs" if s==202 else r.get("detail",""))

print(f"\n{B}{'='*60}{E}")
print(f"{B}  Test 6: Export endpoints{E}")
print(f"{B}{'='*60}{E}")

s, r = req("GET", f"/assets/{domain_id}/export")
test("Export JSON (domain)", s==200, f"keys: {list(r.keys()) if isinstance(r,dict) else 'non-json'}")

import urllib.request as ur
try:
    with ur.urlopen(f"{BASE}/assets/{domain_id}/export?format=csv", timeout=10) as resp:
        csv = resp.read().decode()
        test("Export CSV (domain)", resp.status==200 and "scan_type" in csv, f"{len(csv.splitlines())} lines")
except Exception as e:
    test("Export CSV (domain)", False, str(e))

print(f"\n{B}{'='*60}{E}")
print(f"{B}  SUMMARY{E}")
print(f"{B}{'='*60}{E}")
print(f"  {G}Passed: {len(ok)}{E}  {R}Failed: {len(fail)}{E}")
if fail:
    print(f"\n  {R}Failed tests:{E}")
    for f in fail:
        print(f"    - {f}")

# Cleanup
for asset_id in [domain_id, ip_id, svc_id]:
    if asset_id:
        req("DELETE", f"/assets/batch?ids={asset_id}")
print(f"\n  Test assets cleaned up.")
