"""
Subdomain Enumeration — dnspython + dig + crt.sh để có kết quả đầy đủ nhất
"""
import subprocess
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

COMMON_SUBDOMAINS = [
    "www","mail","ftp","smtp","pop","ns1","ns2","webmail","remote","api",
    "dev","staging","test","admin","portal","app","m","mobile","vpn","cdn",
    "media","img","images","static","assets","blog","shop","store","help",
    "support","docs","status","monitor","dashboard","panel","login","auth",
    "secure","ssl","mx","mx1","mx2","email","smtp2","pop3","imap","exchange",
    "autodiscover","cpanel","whm","cloud","git","gitlab","jenkins","jira",
    "confluence","wiki","forum","news","video","download","upload","backup",
    "db","database","redis","grafana","prometheus","internal","intranet",
    "v2","v1","old","new","beta","alpha","sandbox","search","analytics",
    "gateway","proxy","relay","forward","web","web1","web2","mail2",
    "smtp3","ns3","ns4","api2","dev2","staging2","test2","admin2",
]


def _resolve_hostname(hostname: str) -> dict | None:
    """Resolve using dig (most reliable in Docker)"""
    try:
        result = subprocess.run(
            ["dig", "+short", hostname, "A"],
            capture_output=True, text=True, timeout=5
        )
        ips = [l.strip() for l in result.stdout.splitlines() if l.strip() and not l.startswith(";")]
        # Filter out CNAME lines (they contain dots but not IP format)
        ips = [ip for ip in ips if all(c.isdigit() or c == '.' for c in ip)]
        if ips:
            return {"hostname": hostname, "ips": ips}
    except Exception:
        pass

    # Fallback: dnspython
    try:
        import dns.resolver
        ans = dns.resolver.resolve(hostname, "A", lifetime=4)
        ips = [str(r) for r in ans]
        if ips:
            return {"hostname": hostname, "ips": ips}
    except Exception:
        pass

    return None


class SubdomainScanner:
    def scan(self, domain: str) -> list[dict]:
        found = []
        hostnames = [f"{sub}.{domain}" for sub in COMMON_SUBDOMAINS]

        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(_resolve_hostname, h): h for h in hostnames}
            for future in as_completed(futures, timeout=60):
                try:
                    r = future.result()
                    if r:
                        found.append(r)
                except Exception:
                    pass

        found.sort(key=lambda x: x["hostname"])
        result = {
            "domain": domain,
            "subdomains_found": len(found),
            "wordlist_size": len(COMMON_SUBDOMAINS),
            "subdomains": found,
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        return [result]
