"""
VirusTotal Scanner — domain reputation + OTX threat intel
Free: OTX AlienVault (no key)
With key: VirusTotal v3 API (free tier: 500 req/day)
"""
import os, json, urllib.request, logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def _vt_api(domain: str, api_key: str) -> dict | None:
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        req = urllib.request.Request(
            url, headers={"x-apikey": api_key, "User-Agent": "EASM-Scanner/1.0"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception as e:
        logger.warning("VirusTotal API error: %s", e)
        return None


def _otx_reputation(domain: str) -> dict | None:
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        req = urllib.request.Request(url, headers={"User-Agent": "EASM-Scanner/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception as e:
        logger.warning("OTX general error: %s", e)
        return None


def _otx_passive_dns(domain: str) -> list:
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        req = urllib.request.Request(url, headers={"User-Agent": "EASM-Scanner/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        return data.get("passive_dns", [])[:20]
    except Exception:
        return []


def _otx_malware(domain: str) -> list:
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/malware"
        req = urllib.request.Request(url, headers={"User-Agent": "EASM-Scanner/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        return data.get("data", [])[:10]
    except Exception:
        return []


class VirusTotalScanner:
    def scan(self, domain: str) -> list[dict]:
        api_key = os.getenv("VT_API_KEY", "")

        malicious_count = suspicious_count = harmless_count = reputation = 0
        categories = {}
        vt_available = False

        if api_key:
            vt_data = _vt_api(domain, api_key)
            if vt_data:
                vt_available = True
                attrs = vt_data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious_count  = stats.get("malicious", 0)
                suspicious_count = stats.get("suspicious", 0)
                harmless_count   = stats.get("harmless", 0)
                categories       = attrs.get("categories", {})
                reputation       = attrs.get("reputation", 0)

        otx_general  = _otx_reputation(domain)
        passive_dns  = _otx_passive_dns(domain)
        malware_data = _otx_malware(domain)

        pulse_count    = 0
        otx_reputation = 0
        tags           = []
        if otx_general:
            pulse_count    = otx_general.get("pulse_info", {}).get("count", 0)
            otx_reputation = otx_general.get("reputation", 0)
            tags           = otx_general.get("pulse_info", {}).get("tags", [])[:10]

        # ── Risk assessment — fixed logic ──────────────────────────
        # OTX pulses for popular domains (google, youtube, facebook) are HIGH
        # because researchers monitor them, NOT because they're malicious.
        # Only flag as risky if VT actually detects malicious activity.
        if vt_available:
            if malicious_count > 5:
                risk = "high"
                threat_score = min(100, malicious_count * 10)
            elif malicious_count > 0 or suspicious_count > 2:
                risk = "medium"
                threat_score = malicious_count * 10 + suspicious_count * 3
            else:
                risk = "low"
                threat_score = 0
        else:
            # Without VT, only OTX malware count is truly reliable
            malware_count = len(malware_data)
            if malware_count > 5:
                risk = "medium"
                threat_score = malware_count * 5
            else:
                risk = "low"
                threat_score = malware_count * 3

        result = {
            "domain":       domain,
            "risk_level":   risk,
            "virustotal": {
                "available":   vt_available,
                "reputation":  reputation,
                "malicious":   malicious_count,
                "suspicious":  suspicious_count,
                "harmless":    harmless_count,
                "categories":  categories,
                "note":        "" if api_key else "Set VT_API_KEY env var for VirusTotal data",
            },
            "alienvault_otx": {
                "pulse_count":     pulse_count,
                "reputation":      otx_reputation,
                "tags":            tags,
                "malware_samples": len(malware_data),
                "note":            "High pulse count on popular domains is normal (security monitoring)",
            },
            "passive_dns":  passive_dns,
            "threat_intel": {
                "is_malicious": malicious_count > 0,
                "threat_score": threat_score,
            },
            "created_at":   datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        return [result]
