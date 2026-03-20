"""
DNS Scanner — dùng dnspython + fallback dig
Records: A, AAAA, MX, NS, TXT, CNAME, SOA, SPF
"""
import subprocess
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def _dig_lookup(domain: str, rtype: str) -> list[str]:
    """Dùng dig (dnsutils) để lookup — kết quả chuẩn nhất"""
    try:
        result = subprocess.run(
            ["dig", "+short", domain, rtype],
            capture_output=True, text=True, timeout=10
        )
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        return lines
    except Exception:
        return []


def _dnspython_lookup(domain: str) -> dict:
    """Dùng dnspython nếu có"""
    records = {}
    try:
        import dns.resolver
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
            try:
                ans = dns.resolver.resolve(domain, rtype, lifetime=8)
                records[rtype] = [str(r) for r in ans]
            except Exception:
                pass
        return records
    except ImportError:
        return {}


class DNSScanner:
    def scan(self, domain: str) -> list[dict]:
        # Try dnspython first (more reliable)
        records = _dnspython_lookup(domain)

        # If dnspython not available or returned nothing, use dig
        if not records:
            for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
                vals = _dig_lookup(domain, rtype)
                if vals:
                    records[rtype] = vals

        # SPF is a TXT record — extract separately
        spf = [r for r in records.get("TXT", []) if "v=spf" in r.lower()]
        dmarc = []
        try:
            dmarc_vals = _dig_lookup(f"_dmarc.{domain}", "TXT")
            dmarc = [r for r in dmarc_vals if "v=dmarc" in r.lower()]
        except Exception:
            pass

        result = {
            "domain": domain,
            "records": records,
            "spf": spf,
            "dmarc": dmarc,
            "total_records": sum(len(v) for v in records.values()),
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        return [result]
