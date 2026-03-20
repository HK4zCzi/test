"""
GAU Scanner — GetAllURLs từ:
1. Wayback Machine CDX API (archive.org) — free, no key
2. Common Crawl index API — free, no key
3. AlienVault OTX — free, no key

Tương đương tool gau/waybackurls nhưng dùng public API trực tiếp
"""
import urllib.request
import json
import re
import logging
from datetime import datetime, timezone
from urllib.parse import quote

logger = logging.getLogger(__name__)


def _wayback_urls(domain: str) -> list[str]:
    """Query Wayback Machine CDX API"""
    try:
        url = (f"http://web.archive.org/cdx/search/cdx"
               f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
               f"&limit=500&filter=statuscode:200")
        req = urllib.request.Request(url, headers={"User-Agent": "EASM-Scanner/1.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read())
        # First row is header
        urls = [row[0] for row in data[1:] if row] if len(data) > 1 else []
        return urls
    except Exception as e:
        logger.warning("Wayback Machine error: %s", e)
        return []


def _otx_urls(domain: str) -> list[str]:
    """Query AlienVault OTX for URL data — free, no key"""
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"
        req = urllib.request.Request(url, headers={"User-Agent": "EASM-Scanner/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        urls = [item.get("url", "") for item in data.get("url_list", [])]
        return [u for u in urls if u]
    except Exception as e:
        logger.warning("OTX error: %s", e)
        return []


def _hackertarget_urls(domain: str) -> list[str]:
    """HackerTarget wayback API — free tier"""
    try:
        url = f"https://api.hackertarget.com/pagelinks/?q={domain}"
        req = urllib.request.Request(url, headers={"User-Agent": "EASM-Scanner/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            text = resp.read().decode("utf-8", errors="ignore")
        if "error" in text.lower() or "API count" in text:
            return []
        return [line.strip() for line in text.splitlines() if line.strip().startswith("http")]
    except Exception as e:
        logger.warning("HackerTarget pagelinks error: %s", e)
        return []


def _extract_params(urls: list[str]) -> list[str]:
    """Extract URLs that have query parameters"""
    return [u for u in urls if "?" in u and "=" in u]


def _categorize(urls: list[str]) -> dict[str, list[str]]:
    """Categorize URLs by file extension / type"""
    cats: dict[str, list[str]] = {
        "js": [], "php": [], "asp": [], "api": [],
        "admin": [], "login": [], "upload": [], "other": []
    }
    for u in urls:
        u_low = u.lower().split("?")[0]
        if u_low.endswith(".js"):
            cats["js"].append(u)
        elif u_low.endswith((".php",)):
            cats["php"].append(u)
        elif u_low.endswith((".asp", ".aspx")):
            cats["asp"].append(u)
        elif "/api/" in u_low or "/v1/" in u_low or "/v2/" in u_low:
            cats["api"].append(u)
        elif any(x in u_low for x in ["/admin", "/dashboard", "/panel", "/manager"]):
            cats["admin"].append(u)
        elif any(x in u_low for x in ["/login", "/signin", "/auth", "/oauth"]):
            cats["login"].append(u)
        elif any(x in u_low for x in ["/upload", "/file", "/import"]):
            cats["upload"].append(u)
        else:
            cats["other"].append(u)
    return {k: v[:50] for k, v in cats.items() if v}  # cap per category


class GAUScanner:
    """GetAllURLs — passive URL collection from public sources"""

    def scan(self, domain: str) -> list[dict]:
        all_urls: set[str] = set()

        # Collect from multiple sources
        wayback = _wayback_urls(domain)
        all_urls.update(wayback)
        logger.info("Wayback: %d URLs for %s", len(wayback), domain)

        otx = _otx_urls(domain)
        all_urls.update(otx)
        logger.info("OTX: %d URLs for %s", len(otx), domain)

        ht = _hackertarget_urls(domain)
        all_urls.update(ht)
        logger.info("HackerTarget: %d URLs for %s", len(ht), domain)

        urls_list = sorted(all_urls)[:1000]  # cap total
        with_params = _extract_params(urls_list)
        categorized = _categorize(urls_list)

        result = {
            "domain":        domain,
            "total_urls":    len(all_urls),
            "returned":      len(urls_list),
            "with_params":   len(with_params),
            "sources": {
                "wayback_machine": len(wayback),
                "alienvault_otx":  len(otx),
                "hackertarget":    len(ht),
            },
            "categorized":   categorized,
            "urls_with_params": with_params[:100],
            "sample_urls":   urls_list[:50],
            "created_at":    datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        return [result]
