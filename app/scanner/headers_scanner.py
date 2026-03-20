"""
Security Headers Scanner — dùng requests để check các security headers
"""
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

SECURITY_HEADERS = {
    "strict-transport-security":       {"name":"HSTS",                  "severity":"high",   "desc":"Enforces HTTPS"},
    "content-security-policy":         {"name":"CSP",                   "severity":"high",   "desc":"Prevents XSS/injection"},
    "x-frame-options":                 {"name":"X-Frame-Options",       "severity":"medium", "desc":"Prevents clickjacking"},
    "x-content-type-options":          {"name":"X-Content-Type-Options","severity":"medium", "desc":"Prevents MIME sniffing"},
    "referrer-policy":                 {"name":"Referrer-Policy",       "severity":"low",    "desc":"Controls referrer info"},
    "permissions-policy":              {"name":"Permissions-Policy",    "severity":"low",    "desc":"Browser feature control"},
    "cross-origin-opener-policy":      {"name":"COOP",                  "severity":"medium", "desc":"Isolates browsing context"},
    "cross-origin-embedder-policy":    {"name":"COEP",                  "severity":"low",    "desc":"Embedding control"},
    "cross-origin-resource-policy":    {"name":"CORP",                  "severity":"low",    "desc":"Resource sharing control"},
}


class HeadersScanner:
    def scan(self, domain: str) -> list[dict]:
        import requests
        headers_found = {}

        for scheme in ("https", "http"):
            try:
                resp = requests.get(
                    f"{scheme}://{domain}",
                    headers={"User-Agent": "Mozilla/5.0 EASM-Scanner/1.0"},
                    timeout=10, allow_redirects=True, verify=False,
                )
                headers_found = {k.lower(): v for k, v in resp.headers.items()}
                break
            except Exception:
                continue

        if not headers_found:
            raise ValueError(f"Cannot reach {domain}")

        present, missing = [], []
        missing_high, missing_medium = [], []

        for hkey, meta in SECURITY_HEADERS.items():
            if hkey in headers_found:
                present.append({
                    "header": meta["name"],
                    "value": headers_found[hkey][:200],
                    "status": "present",
                    "severity": meta["severity"],
                })
            else:
                entry = {"header": meta["name"], "status": "missing",
                         "severity": meta["severity"], "description": meta["desc"]}
                missing.append(entry)
                if meta["severity"] == "high":
                    missing_high.append(meta["name"])
                elif meta["severity"] == "medium":
                    missing_medium.append(meta["name"])

        if not missing_high and not missing_medium:
            grade = "A"
        elif not missing_high:
            grade = "B"
        elif len(missing_high) == 1:
            grade = "C"
        else:
            grade = "D"

        return [{
            "domain": domain,
            "grade": grade,
            "headers_present": len(present),
            "headers_missing": len(missing),
            "present": present,
            "missing": missing,
            "all_headers": {k: v[:100] for k, v in list(headers_found.items())[:25]},
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }]
