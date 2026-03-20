"""
WAF Scanner — detect WAF on main domain + all subdomains
Dùng wafw00f CLI + header analysis fallback
"""
import subprocess, json, re, socket, urllib.request, logging
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

WAF_SIGS = [
    {"name":"Cloudflare",   "headers":{"server":"cloudflare","cf-ray":None},          "cookies":{"__cflb","cf_clearance","__cf_bm"}},
    {"name":"AWS WAF",      "headers":{"x-amzn-requestid":None,"x-amz-cf-id":None},   "cookies":{"aws-waf-token"}},
    {"name":"Akamai",       "headers":{"x-check-cacheable":None},                     "cookies":{"ak_bmsc","bm_sz"}},
    {"name":"Imperva",      "headers":{"x-iinfo":None},                               "cookies":{"incap_ses","visid_incap"}},
    {"name":"Sucuri",       "headers":{"x-sucuri-id":None},                           "cookies":set()},
    {"name":"Fastly",       "headers":{"x-fastly-request-id":None},                  "cookies":set()},
    {"name":"ModSecurity",  "headers":{"server":"mod_security"},                      "cookies":set()},
    {"name":"F5 BIG-IP",    "headers":{"x-waf-status":None},                         "cookies":{"ts","tsrce"}},
    {"name":"Varnish",      "headers":{"x-varnish":None},                            "cookies":set()},
    {"name":"Nginx",        "headers":{"server":"nginx"},                             "cookies":set()},
    {"name":"Google",       "headers":{"server":"gws","server":"sffe","server":"esf"},"cookies":set()},
]


def _wafw00f_scan(domain: str) -> dict | None:
    try:
        result = subprocess.run(
            ["wafw00f", "-f", "json", "-o", "/dev/stdout", f"https://{domain}"],
            capture_output=True, text=True, timeout=25
        )
        # wafw00f outputs JSON to stdout or a file
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("["):
                data = json.loads(line)
                if data:
                    entry = data[0]
                    return {
                        "detected":      entry.get("detected", False),
                        "waf":           entry.get("firewall"),
                        "manufacturer":  entry.get("manufacturer"),
                    }
        # Parse text output fallback
        out = result.stdout + result.stderr
        if "is behind" in out:
            m = re.search(r"is behind (.+?)(?:\s+WAF|\s+firewall)", out, re.IGNORECASE)
            waf = m.group(1).strip() if m else "Unknown WAF"
            return {"detected": True, "waf": waf, "manufacturer": None}
        if "No WAF" in out or "generic" in out.lower():
            return {"detected": False, "waf": None, "manufacturer": None}
    except FileNotFoundError:
        pass
    except Exception as e:
        logger.debug("wafw00f error for %s: %s", domain, e)
    return None


def _header_detect(domain: str) -> dict:
    headers_found = {}
    cookies_found = set()
    status = 0
    try:
        import requests
        resp = requests.get(
            f"https://{domain}",
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=8, verify=False, allow_redirects=True,
        )
        headers_found = {k.lower(): v.lower() for k, v in resp.headers.items()}
        for c in resp.cookies.keys():
            cookies_found.add(c.lower())
        status = resp.status_code
    except Exception:
        pass

    best = {"detected": False, "waf": None, "confidence": 0, "evidence": []}
    for sig in WAF_SIGS:
        score = 0
        evidence = []
        for h_key, h_val in sig["headers"].items():
            if h_key in headers_found:
                if h_val is None or h_val in headers_found.get(h_key, ""):
                    score += 2
                    evidence.append(f"header:{h_key}={headers_found[h_key][:40]}")
        for c in sig.get("cookies", set()):
            if c in cookies_found:
                score += 2
                evidence.append(f"cookie:{c}")
        if score > best["confidence"]:
            best = {"detected": score >= 2, "waf": sig["name"] if score >= 2 else None,
                    "confidence": score, "evidence": evidence}
    best["http_status"] = status
    return best


def _scan_single(domain: str) -> dict:
    """Scan one domain for WAF"""
    # Try wafw00f first
    wf = _wafw00f_scan(domain)
    if wf and wf.get("detected") is not None:
        return {
            "domain":    domain,
            "detected":  wf["detected"],
            "waf":       wf.get("waf"),
            "method":    "wafw00f",
            "confidence": 90 if wf["detected"] else 0,
        }
    # Fallback headers
    hd = _header_detect(domain)
    return {
        "domain":     domain,
        "detected":   hd["detected"],
        "waf":        hd.get("waf"),
        "method":     "header-analysis",
        "confidence": min(100, hd.get("confidence", 0) * 25),
        "evidence":   hd.get("evidence", []),
        "http_status":hd.get("http_status", 0),
    }


def _get_subdomains(domain: str) -> list[str]:
    """Quick subdomain resolve for WAF scan coverage"""
    common = ["www","api","mail","m","app","admin","cdn","static","dev","staging","blog"]
    found = []
    for sub in common:
        hostname = f"{sub}.{domain}"
        try:
            socket.gethostbyname(hostname)
            found.append(hostname)
        except Exception:
            pass
    return found


class WAFScanner:
    def scan(self, domain: str, scan_subdomains: bool = True) -> list[dict]:
        targets = [domain]
        if scan_subdomains:
            subs = _get_subdomains(domain)
            targets.extend(subs)

        results_map = {}
        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = {ex.submit(_scan_single, t): t for t in targets}
            for future in as_completed(futures, timeout=60):
                t = futures[future]
                try:
                    results_map[t] = future.result()
                except Exception as e:
                    results_map[t] = {"domain": t, "detected": False, "waf": None,
                                       "method": "error", "error": str(e)}

        scanned = [results_map.get(t, {}) for t in targets]
        wafs_found = {r["waf"] for r in scanned if r.get("detected") and r.get("waf")}
        domains_with_waf = [r["domain"] for r in scanned if r.get("detected")]

        result = {
            "domain":            domain,
            "waf_detected":      len(wafs_found) > 0,
            "waf_name":          list(wafs_found)[0] if wafs_found else None,
            "all_wafs":          list(wafs_found),
            "domains_scanned":   len(scanned),
            "domains_with_waf":  domains_with_waf,
            "per_domain":        scanned,
            "detection_method":  "wafw00f+headers",
            "created_at":        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        return [result]
