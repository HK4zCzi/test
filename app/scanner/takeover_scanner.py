"""
Subdomain Takeover Scanner — check CNAME → unclaimed service fingerprints
"""
import subprocess, re, logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

TAKEOVER_SIGS = [
    {"service":"GitHub Pages",   "cname":["github.io"],                    "body":["there isn't a github pages site here","for root url"]},
    {"service":"Heroku",         "cname":["herokuapp.com","heroku.com"],   "body":["no such app","herokucdn.com/error-pages"]},
    {"service":"AWS S3",         "cname":["s3.amazonaws.com","s3-website"],"body":["nosuchbucket","the specified bucket does not exist"]},
    {"service":"Netlify",        "cname":["netlify.app","netlify.com"],    "body":["not found - request id","page not found"]},
    {"service":"Shopify",        "cname":["myshopify.com"],                "body":["sorry, this shop is currently unavailable"]},
    {"service":"Fastly",         "cname":["fastly.net"],                   "body":["fastly error: unknown domain"]},
    {"service":"Ghost",          "cname":["ghost.io"],                     "body":["the thing you were looking for is no longer here"]},
    {"service":"Tumblr",         "cname":["tumblr.com"],                   "body":["whatever you were looking for doesn't currently exist"]},
    {"service":"Azure",          "cname":["azurewebsites.net","cloudapp.net","trafficmanager.net"],"body":["404 web site not found","doesn't exist"]},
    {"service":"Pantheon",       "cname":["pantheonsite.io"],              "body":["the gods are wise","404 error unknown site"]},
    {"service":"Surge.sh",       "cname":["surge.sh"],                     "body":["project not found"]},
    {"service":"Zendesk",        "cname":["zendesk.com"],                  "body":["help center closed","Redirecting"]},
]


def _get_cname(domain: str) -> list[str]:
    try:
        result = subprocess.run(
            ["dig", "+short", domain, "CNAME"],
            capture_output=True, text=True, timeout=8
        )
        return [l.strip().rstrip(".") for l in result.stdout.splitlines() if l.strip()]
    except Exception:
        return []


def _get_body(domain: str) -> tuple[str, int]:
    try:
        import requests
        for scheme in ("https", "http"):
            try:
                resp = requests.get(
                    f"{scheme}://{domain}",
                    headers={"User-Agent": "Mozilla/5.0"},
                    timeout=8, allow_redirects=True, verify=False,
                )
                return resp.text.lower()[:8192], resp.status_code
            except Exception:
                continue
    except ImportError:
        pass
    return "", 0


class TakeoverScanner:
    def scan(self, domain: str) -> list[dict]:
        cname_chain = _get_cname(domain)
        body, status = _get_body(domain)

        vulnerable = []
        for sig in TAKEOVER_SIGS:
            cname_match = any(
                any(c in cname.lower() for cname in cname_chain)
                for c in sig["cname"]
            )
            body_match = any(fp in body for fp in sig["body"])

            if cname_match and body_match:
                vulnerable.append({
                    "service": sig["service"],
                    "cname_chain": cname_chain,
                    "fingerprints_matched": [fp for fp in sig["body"] if fp in body],
                    "severity": "critical",
                })
            elif cname_match and status in (404, 0):
                vulnerable.append({
                    "service": sig["service"],
                    "cname_chain": cname_chain,
                    "fingerprints_matched": [],
                    "severity": "medium",
                    "note": "CNAME points to service but body fingerprint not confirmed",
                })

        return [{
            "domain":          domain,
            "vulnerable":      len(vulnerable) > 0,
            "vulnerabilities": vulnerable,
            "cname_chain":     cname_chain,
            "http_status":     status,
            "created_at":      datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }]
