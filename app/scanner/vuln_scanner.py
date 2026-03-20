"""
Vulnerability Scanners — XSS, SSRF, CRLF detection
Active scans: sends test payloads to target URLs
ONLY use on systems you own or have permission to test
"""
import re
import logging
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

# ── XSS Scanner ────────────────────────────────────────────────────
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    '<svg onload=alert(1)>',
    '{{7*7}}',           # template injection probe
    '${7*7}',
]

XSS_REFLECTED_PATTERNS = [
    r'<script>alert\(1\)</script>',
    r'alert\(1\)',
    r'onerror=alert',
    r'<svg onload',
    r'49',  # 7*7 template injection result
]


def _test_xss_param(base_url: str, param: str, payload: str) -> dict | None:
    """Test one URL parameter for reflected XSS"""
    try:
        import requests
        url = f"{base_url}?{param}={payload}"
        resp = requests.get(
            url, headers={"User-Agent": "Mozilla/5.0 EASM-XSS-Scanner/1.0"},
            timeout=8, verify=False, allow_redirects=True
        )
        body = resp.text
        for pattern in XSS_REFLECTED_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                return {
                    "url":         url,
                    "param":       param,
                    "payload":     payload,
                    "type":        "Reflected XSS",
                    "evidence":    f"Pattern '{pattern}' found in response",
                    "status_code": resp.status_code,
                    "severity":    "high",
                }
    except Exception:
        pass
    return None


class XSSScanner:
    """Reflected XSS scanner — tests URL parameters with payloads"""

    def scan(self, domain: str) -> list[dict]:
        import requests

        # First get URLs with parameters
        base_urls = [f"https://{domain}", f"http://{domain}"]
        test_params = ["q", "search", "id", "query", "name", "input",
                       "page", "url", "redirect", "ref", "return"]

        findings = []
        tested = 0

        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = []
            for base_url in base_urls[:1]:  # test HTTPS only
                for param in test_params[:5]:  # limit to 5 params
                    for payload in XSS_PAYLOADS[:3]:  # top 3 payloads
                        futures.append(
                            ex.submit(_test_xss_param, base_url, param, payload)
                        )
                        tested += 1

            for future in as_completed(futures, timeout=60):
                result = future.result()
                if result:
                    findings.append(result)

        return [{
            "domain":       domain,
            "type":         "xss",
            "tested":       tested,
            "findings":     findings,
            "vulnerable":   len(findings) > 0,
            "severity":     "high" if findings else "none",
            "disclaimer":   "⚠️ Only test on systems you own or have permission to test",
            "created_at":   datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }]


# ── SSRF Scanner ───────────────────────────────────────────────────
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",   # AWS metadata
    "http://metadata.google.internal/",            # GCP metadata
    "http://169.254.169.254/metadata/v1/",         # DO metadata
    "http://localhost/",
    "http://127.0.0.1/",
    "http://0.0.0.0/",
]

SSRF_PARAMS = ["url", "redirect", "next", "callback", "return",
               "target", "dest", "destination", "link", "src", "path"]

SSRF_INDICATORS = [
    "ami-id", "instance-id", "local-ipv4",  # AWS
    "computeMetadata", "numericProjectId",   # GCP
    "droplet_id", "vendor-data",             # DigitalOcean
    "root:x:0:0",                            # /etc/passwd
]


def _test_ssrf_param(base_url: str, param: str, payload: str) -> dict | None:
    try:
        import requests
        url = f"{base_url}?{param}={payload}"
        resp = requests.get(
            url, headers={"User-Agent": "Mozilla/5.0 EASM-SSRF-Scanner/1.0"},
            timeout=5, verify=False, allow_redirects=False,
        )
        body = resp.text
        for indicator in SSRF_INDICATORS:
            if indicator.lower() in body.lower():
                return {
                    "url":      url,
                    "param":    param,
                    "payload":  payload,
                    "type":     "SSRF",
                    "evidence": f"Sensitive data indicator: '{indicator}'",
                    "severity": "critical",
                }
        # Check for redirect to internal IP
        location = resp.headers.get("location", "")
        if any(ip in location for ip in ["127.", "169.254.", "10.", "192.168.", "metadata"]):
            return {
                "url":      url,
                "param":    param,
                "payload":  payload,
                "type":     "SSRF (Open Redirect to internal)",
                "evidence": f"Location header: {location}",
                "severity": "high",
            }
    except Exception:
        pass
    return None


class SSRFScanner:
    def scan(self, domain: str) -> list[dict]:
        findings = []
        tested = 0
        base_url = f"https://{domain}"

        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = []
            for param in SSRF_PARAMS[:6]:
                for payload in SSRF_PAYLOADS[:3]:
                    futures.append(ex.submit(_test_ssrf_param, base_url, param, payload))
                    tested += 1
            for future in as_completed(futures, timeout=60):
                result = future.result()
                if result:
                    findings.append(result)

        return [{
            "domain":     domain,
            "type":       "ssrf",
            "tested":     tested,
            "findings":   findings,
            "vulnerable": len(findings) > 0,
            "severity":   "critical" if any(f["severity"] == "critical" for f in findings)
                          else "high" if findings else "none",
            "disclaimer": "⚠️ Only test on systems you own",
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }]


# ── CRLF Scanner ───────────────────────────────────────────────────
CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:crlf=injected",
    "%0aSet-Cookie:crlf=injected",
    "%0d%0aX-CRLF-Test:injected",
    "\r\nSet-Cookie:crlf=injected",
    "%E5%98%8A%E5%98%8DSet-Cookie:crlf=injected",  # Unicode bypass
]

CRLF_TEST_PARAMS = ["redirect", "url", "next", "return", "path", "lang", "location"]


def _test_crlf(base_url: str, param: str, payload: str) -> dict | None:
    try:
        import requests
        url = f"{base_url}?{param}={payload}"
        resp = requests.get(
            url, headers={"User-Agent": "Mozilla/5.0 EASM-CRLF-Scanner/1.0"},
            timeout=8, verify=False, allow_redirects=False,
        )
        # Check if injected header appears in response
        if "crlf" in str(resp.headers).lower() or "crlf=injected" in str(resp.cookies):
            return {
                "url":      url,
                "param":    param,
                "payload":  payload,
                "type":     "CRLF Injection",
                "evidence": f"Injected header/cookie found in response",
                "headers":  dict(resp.headers),
                "severity": "high",
            }
    except Exception:
        pass
    return None


class CRLFScanner:
    def scan(self, domain: str) -> list[dict]:
        findings = []
        tested = 0
        base_url = f"https://{domain}"

        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = []
            for param in CRLF_TEST_PARAMS[:5]:
                for payload in CRLF_PAYLOADS[:3]:
                    futures.append(ex.submit(_test_crlf, base_url, param, payload))
                    tested += 1
            for future in as_completed(futures, timeout=60):
                result = future.result()
                if result:
                    findings.append(result)

        return [{
            "domain":     domain,
            "type":       "crlf",
            "tested":     tested,
            "findings":   findings,
            "vulnerable": len(findings) > 0,
            "severity":   "high" if findings else "none",
            "disclaimer": "⚠️ Only test on systems you own",
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }]
