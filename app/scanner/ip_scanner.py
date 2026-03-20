"""
IP Scanner — Geolocation + ASN + Reverse DNS
Dùng nhiều API fallback để đảm bảo luôn có kết quả:
1. ipapi.co (free, no key, reliable)
2. ip-api.com HTTP (free, 45 req/min)
3. ipinfo.io (free, 50k/month)
"""
import socket
import json
import urllib.request
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def _ipapi_co(ip: str) -> dict | None:
    """ipapi.co — free, no key, very reliable"""
    try:
        url = f"https://ipapi.co/{ip}/json/"
        req = urllib.request.Request(url, headers={"User-Agent": "EASM-Scanner/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        if data.get("error"):
            return None
        return {
            "country":      data.get("country_name", ""),
            "country_code": data.get("country_code", ""),
            "city":         data.get("city", ""),
            "region":       data.get("region", ""),
            "latitude":     data.get("latitude", 0),
            "longitude":    data.get("longitude", 0),
            "isp":          data.get("org", ""),
            "org":          data.get("org", ""),
            "asn_raw":      data.get("asn", ""),
        }
    except Exception as e:
        logger.warning("ipapi.co error: %s", e)
        return None


def _ipinfo_io(ip: str) -> dict | None:
    """ipinfo.io — free 50k/month, no key needed for basic"""
    try:
        url = f"https://ipinfo.io/{ip}/json"
        req = urllib.request.Request(url, headers={"User-Agent": "EASM-Scanner/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        loc = data.get("loc", "0,0").split(",")
        return {
            "country":      data.get("country", ""),
            "country_code": data.get("country", ""),
            "city":         data.get("city", ""),
            "region":       data.get("region", ""),
            "latitude":     float(loc[0]) if len(loc) > 0 else 0,
            "longitude":    float(loc[1]) if len(loc) > 1 else 0,
            "isp":          data.get("org", ""),
            "org":          data.get("org", ""),
            "asn_raw":      data.get("org", "").split(" ")[0] if data.get("org") else "",
        }
    except Exception as e:
        logger.warning("ipinfo.io error: %s", e)
        return None


def _ip_api_com(ip: str) -> dict | None:
    """ip-api.com HTTP — free, 45 req/min"""
    try:
        url = (f"http://ip-api.com/json/{ip}"
               f"?fields=status,country,countryCode,regionName,city,lat,lon,isp,org,as,reverse")
        req = urllib.request.Request(url, headers={"User-Agent": "EASM-Scanner/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())
        if data.get("status") != "success":
            return None
        return {
            "country":      data.get("country", ""),
            "country_code": data.get("countryCode", ""),
            "city":         data.get("city", ""),
            "region":       data.get("regionName", ""),
            "latitude":     data.get("lat", 0),
            "longitude":    data.get("lon", 0),
            "isp":          data.get("isp", ""),
            "org":          data.get("org", ""),
            "asn_raw":      data.get("as", ""),
        }
    except Exception as e:
        logger.warning("ip-api.com error: %s", e)
        return None


class IPScanner:
    def scan(self, ip_address: str) -> list[dict]:
        # Try APIs in order, use first that works
        geo = None
        source = ""
        for fn, name in [(_ipapi_co, "ipapi.co"), (_ipinfo_io, "ipinfo.io"), (_ip_api_com, "ip-api.com")]:
            geo = fn(ip_address)
            if geo:
                source = name
                break

        if not geo:
            raise ValueError(f"All geo APIs failed for {ip_address}")

        # Parse ASN
        asn_raw = geo.pop("asn_raw", "")
        asn_number, asn_name = 0, ""
        if asn_raw:
            parts = asn_raw.split(" ", 1)
            try:
                asn_number = int(parts[0].replace("AS", ""))
                asn_name = parts[1] if len(parts) > 1 else ""
            except (ValueError, IndexError):
                asn_name = asn_raw

        # Reverse DNS
        reverse_dns = ""
        try:
            reverse_dns = socket.gethostbyaddr(ip_address)[0]
        except Exception:
            pass

        result = {
            "ip_address":  ip_address,
            "geolocation": geo,
            "asn": {
                "number":      asn_number,
                "name":        asn_name,
                "description": geo.get("org", ""),
            },
            "reverse_dns": reverse_dns,
            "data_source": source,
            "created_at":  datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        return [result]
