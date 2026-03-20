"""
CORS Scanner — kiểm tra CORS misconfiguration
Test các case: arbitrary origin, null origin, subdomain wildcard
"""
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

TEST_ORIGINS = [
    "https://evil.com",
    "https://evil.youtube.com",
    "null",
    "https://attacker.com",
]

ENDPOINTS_TO_TEST = ["/", "/api/", "/api/v1/", "/graphql"]


def _test_cors(domain: str, path: str, origin: str) -> dict | None:
    """Send request with Origin header, check ACAO response"""
    try:
        import requests
        url = f"https://{domain}{path}"
        resp = requests.options(
            url,
            headers={
                "Origin":                         origin,
                "Access-Control-Request-Method":  "GET",
                "Access-Control-Request-Headers": "Authorization,Content-Type",
                "User-Agent": "Mozilla/5.0 EASM-Scanner/1.0",
            },
            timeout=8,
            verify=False,
            allow_redirects=False,
        )
        acao  = resp.headers.get("Access-Control-Allow-Origin", "")
        acac  = resp.headers.get("Access-Control-Allow-Credentials", "")
        acam  = resp.headers.get("Access-Control-Allow-Methods", "")
        acah  = resp.headers.get("Access-Control-Allow-Headers", "")

        if not acao:
            return None

        # Determine severity
        vuln = False
        severity = "info"
        desc = ""

        if acao == origin and acac.lower() == "true":
            vuln = True
            severity = "critical"
            desc = f"Reflects arbitrary Origin with credentials: {origin}"
        elif acao == origin:
            vuln = True
            severity = "high"
            desc = f"Reflects arbitrary Origin (no credentials): {origin}"
        elif acao == "*" and acac.lower() == "true":
            vuln = True
            severity = "high"
            desc = "Wildcard * with credentials — browser ignores but misconfigured"
        elif acao == "null":
            vuln = True
            severity = "medium"
            desc = "null origin allowed — sandboxed iframe bypass possible"
        elif acao == "*":
            severity = "info"
            desc = "Wildcard CORS — public API (acceptable for public endpoints)"

        return {
            "endpoint":    f"https://{domain}{path}",
            "origin_sent": origin,
            "acao":        acao,
            "acac":        acac,
            "acam":        acam,
            "acah":        acah[:100],
            "vulnerable":  vuln,
            "severity":    severity,
            "description": desc,
        }
    except Exception:
        return None


class CORSScanner:
    """CORS misconfiguration checker"""

    def scan(self, domain: str) -> list[dict]:
        findings = []
        tested = 0

        for path in ENDPOINTS_TO_TEST:
            for origin in TEST_ORIGINS:
                finding = _test_cors(domain, path, origin)
                tested += 1
                if finding:
                    findings.append(finding)

        vulnerabilities = [f for f in findings if f.get("vulnerable")]
        vuln_count = len(vulnerabilities)

        if vuln_count == 0:
            risk = "low"
        elif any(f["severity"] == "critical" for f in vulnerabilities):
            risk = "critical"
        elif any(f["severity"] == "high" for f in vulnerabilities):
            risk = "high"
        else:
            risk = "medium"

        result = {
            "domain":          domain,
            "risk":            risk,
            "tests_run":       tested,
            "findings":        findings,
            "vulnerabilities": vulnerabilities,
            "vuln_count":      vuln_count,
            "created_at":      datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        return [result]
