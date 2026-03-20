"""
URLScan.io Scanner — passive website intelligence từ public scans
API public (search), no key needed. Submit scan cần key.
"""
import json
import urllib.request
import urllib.parse
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def _search_urlscan(domain: str) -> list[dict]:
    """Search existing scans — free, no key"""
    try:
        query = urllib.parse.quote(f"domain:{domain}")
        url = f"https://urlscan.io/api/v1/search/?q={query}&size=10"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "EASM-Scanner/1.0"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        return data.get("results", [])
    except Exception as e:
        logger.warning("URLScan search error: %s", e)
        return []


def _submit_urlscan(domain: str, api_key: str) -> dict | None:
    """Submit new scan — needs API key (free at urlscan.io)"""
    import os
    if not api_key:
        return None
    try:
        payload = json.dumps({"url": f"https://{domain}", "visibility": "public"}).encode()
        req = urllib.request.Request(
            "https://urlscan.io/api/v1/scan/",
            data=payload,
            headers={
                "API-Key":      api_key,
                "Content-Type": "application/json",
                "User-Agent":   "EASM-Scanner/1.0",
            }
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception as e:
        logger.warning("URLScan submit error: %s", e)
        return None


class URLScanScanner:
    """URLScan.io — website intelligence from passive scans"""

    def scan(self, domain: str) -> list[dict]:
        import os
        api_key = os.getenv("URLSCAN_API_KEY", "")

        existing_scans = _search_urlscan(domain)

        screenshots = []
        technologies_seen: set[str] = set()
        ips_seen: set[str] = set()
        countries_seen: set[str] = set()
        malicious_count = 0
        scan_summaries = []

        for scan in existing_scans[:10]:
            result = scan.get("result", "")
            page = scan.get("page", {})
            task = scan.get("task", {})
            stats = scan.get("stats", {})

            ip = page.get("ip", "")
            country = page.get("country", "")
            if ip:
                ips_seen.add(ip)
            if country:
                countries_seen.add(country)

            # Screenshot URL
            uuid = scan.get("_id", "")
            if uuid:
                screenshots.append(f"https://urlscan.io/screenshots/{uuid}.png")

            if stats.get("malicious", 0) > 0:
                malicious_count += 1

            scan_summaries.append({
                "uuid":       uuid,
                "time":       task.get("time", ""),
                "url":        page.get("url", ""),
                "ip":         ip,
                "country":    country,
                "server":     page.get("server", ""),
                "status":     page.get("status", 0),
                "screenshot": f"https://urlscan.io/screenshots/{uuid}.png" if uuid else "",
                "report":     f"https://urlscan.io/result/{uuid}/" if uuid else "",
            })

        # Try to submit new scan if we have API key
        submit_result = None
        if api_key and existing_scans:
            pass  # Already have recent data, skip submit
        elif api_key:
            submit_result = _submit_urlscan(domain, api_key)

        result = {
            "domain":           domain,
            "scans_found":      len(existing_scans),
            "malicious_scans":  malicious_count,
            "ips_seen":         list(ips_seen),
            "countries_seen":   list(countries_seen),
            "screenshots":      screenshots[:5],
            "recent_scans":     scan_summaries,
            "submit_result":    submit_result,
            "note": "Set URLSCAN_API_KEY for new scan submission" if not api_key else "",
            "created_at":       datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        return [result]
