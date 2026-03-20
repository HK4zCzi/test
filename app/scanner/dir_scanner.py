"""
Directory Scanner — brute force common paths
Tương đương ffuf/dirsearch nhưng nhẹ hơn, focus vào high-value paths
"""
import logging
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

# High-value paths to check
WORDLIST = [
    # Admin panels
    "admin", "admin/", "administrator", "admin/login", "admin/dashboard",
    "wp-admin", "wp-login.php", "wp-admin/", "phpmyadmin", "pma",
    "cpanel", "plesk", "directadmin", "webmin",
    # APIs
    "api", "api/v1", "api/v2", "api/v3", "graphql", "rest",
    "api/users", "api/admin", "api/config", "api/debug",
    # Dev/debug
    "debug", "test", "dev", "staging", "backup", "old", "temp",
    ".env", ".git", ".git/config", ".svn", ".DS_Store",
    "config", "config.php", "config.json", "configuration",
    "settings", "settings.php", "database.php",
    # Sensitive files
    "robots.txt", "sitemap.xml", "crossdomain.xml", "security.txt",
    ".well-known/security.txt", "humans.txt", "license.txt",
    "readme.md", "README.md", "CHANGELOG.md",
    # Cloud / infra
    "aws.json", "credentials", ".aws/credentials",
    "docker-compose.yml", "Dockerfile", "kubernetes.yml",
    # Common endpoints
    "login", "logout", "register", "signup", "signin",
    "forgot-password", "reset-password", "change-password",
    "profile", "account", "dashboard", "console",
    "upload", "uploads", "files", "downloads",
    "search", "export", "import", "backup",
    # Health / status
    "health", "healthz", "status", "ping", "version",
    "metrics", "prometheus", "actuator", "actuator/health",
    # Logs
    "logs", "log", "error_log", "access_log",
    "server-status", "server-info",
]

INTERESTING_STATUS = {200, 201, 204, 301, 302, 401, 403, 405, 500}


def _check_path(domain: str, path: str) -> dict | None:
    try:
        import requests
        url = f"https://{domain}/{path.lstrip('/')}"
        resp = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0 EASM-Scanner/1.0"},
            timeout=6,
            allow_redirects=False,
            verify=False,
        )
        if resp.status_code in INTERESTING_STATUS:
            content_type = resp.headers.get("content-type", "")
            return {
                "path":         f"/{path.lstrip('/')}",
                "url":          url,
                "status":       resp.status_code,
                "size":         len(resp.content),
                "content_type": content_type[:60],
                "interesting":  resp.status_code in {200, 201, 401, 403, 500},
                "severity":     _assess_severity(path, resp.status_code),
            }
    except Exception:
        pass
    return None


def _assess_severity(path: str, status: int) -> str:
    high_paths = {".env", ".git", "config", "credentials", "backup", "phpmyadmin", "pma"}
    medium_paths = {"admin", "debug", "test", "dev", "wp-admin", "actuator"}
    for p in high_paths:
        if p in path.lower():
            return "high" if status in {200, 201} else "medium"
    for p in medium_paths:
        if p in path.lower():
            return "medium"
    return "info"


class DirScanner:
    """Directory and file brute force scanner"""

    def scan(self, domain: str) -> list[dict]:
        found = []

        with ThreadPoolExecutor(max_workers=15) as ex:
            futures = {ex.submit(_check_path, domain, path): path for path in WORDLIST}
            for future in as_completed(futures, timeout=120):
                try:
                    r = future.result()
                    if r:
                        found.append(r)
                except Exception:
                    pass

        found.sort(key=lambda x: (
            {"high": 0, "medium": 1, "info": 2}.get(x["severity"], 3),
            -x["status"]
        ))

        high = [f for f in found if f["severity"] == "high"]
        medium = [f for f in found if f["severity"] == "medium"]

        result = {
            "domain":        domain,
            "paths_tested":  len(WORDLIST),
            "paths_found":   len(found),
            "high_risk":     len(high),
            "medium_risk":   len(medium),
            "risk": "high" if high else ("medium" if medium else "low"),
            "findings":      found,
            "created_at":    datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        return [result]
