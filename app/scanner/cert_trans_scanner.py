"""
Certificate Transparency — query crt.sh + hackertarget.com
Phát hiện subdomain qua CT logs không cần active scan
"""
import urllib.request, json, logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class CertTransScanner:
    def scan(self, domain: str) -> list[dict]:
        try:
            import requests
            resp = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                headers={"User-Agent": "EASM-Scanner/1.0"},
                timeout=20,
            )
            data = resp.json()
        except Exception:
            # Fallback urllib
            try:
                req = urllib.request.Request(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    headers={"User-Agent": "EASM-Scanner/1.0"},
                )
                with urllib.request.urlopen(req, timeout=20) as r:
                    data = json.loads(r.read())
            except Exception as e:
                raise ValueError(f"crt.sh lookup failed: {e}") from e

        # Deduplicate
        seen = set()
        certs = []
        domain_set = set()

        for entry in data:
            cert_id = entry.get("id", "")
            names = entry.get("name_value", "").split("\n")
            for name in names:
                name = name.strip().lstrip("*.")
                if not name or name in seen:
                    continue
                seen.add(name)
                domain_set.add(name)
                certs.append({
                    "name":       name,
                    "issuer":     entry.get("issuer_name", "")[:80],
                    "not_before": entry.get("not_before", ""),
                    "not_after":  entry.get("not_after", ""),
                    "cert_id":    cert_id,
                })

        # Sort: subdomains first
        certs.sort(key=lambda x: x["name"])

        return [{
            "domain":             domain,
            "certificates_found": len(certs),
            "unique_domains":     sorted(domain_set),
            "certificates":       certs[:200],
            "source":             "crt.sh",
            "created_at":         datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }]
