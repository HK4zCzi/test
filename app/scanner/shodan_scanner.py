"""
Shodan Scanner — Internet-wide scanning data
- Shodan API (khi có SHODAN_API_KEY)
- BGPView API (free, no key — ASN + prefix data)
- HackerTarget (free, no key — basic port/geo data)
- Censys Search (khi có CENSYS_API_ID + CENSYS_SECRET)
"""
import os, json, socket, urllib.request, logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def _shodan_official(ip: str, key: str) -> dict | None:
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={key}"
        req = urllib.request.Request(url, headers={"User-Agent": "EASM-Scanner/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception as e:
        logger.warning("Shodan API: %s", e)
        return None


def _bgpview_asn(ip: str) -> dict | None:
    """BGPView — free, no key, returns ASN + prefix for any IP"""
    try:
        url = f"https://api.bgpview.io/ip/{ip}"
        req = urllib.request.Request(url, headers={"User-Agent": "EASM-Scanner/1.0"})
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read())
        if data.get("status") != "ok":
            return None
        prefixes = data.get("data", {}).get("prefixes", [])
        if not prefixes:
            return None
        p = prefixes[0]
        asn_info = p.get("asn", {})
        return {
            "asn_number":     asn_info.get("asn", 0),
            "asn_name":       asn_info.get("name", ""),
            "asn_description":asn_info.get("description", ""),
            "asn_country":    asn_info.get("country_code", ""),
            "prefix":         p.get("prefix", ""),
            "name":           p.get("name", ""),
            "description":    p.get("description", ""),
        }
    except Exception as e:
        logger.warning("BGPView error: %s", e)
        return None


def _hackertarget_ports(ip: str) -> list[int]:
    """HackerTarget nmap scan (free, limited)"""
    try:
        url = f"https://api.hackertarget.com/nmap/?q={ip}"
        req = urllib.request.Request(url, headers={"User-Agent": "EASM-Scanner/1.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            text = resp.read().decode("utf-8", errors="ignore")
        if "error" in text.lower() or "API count" in text:
            return []
        import re
        ports = []
        for m in re.finditer(r'(\d+)/tcp\s+open', text):
            ports.append(int(m.group(1)))
        return ports
    except Exception as e:
        logger.warning("HackerTarget nmap: %s", e)
        return []


def _hackertarget_geo(ip: str) -> dict:
    try:
        url = f"https://api.hackertarget.com/geoip/?q={ip}"
        req = urllib.request.Request(url, headers={"User-Agent": "EASM-Scanner/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            text = resp.read().decode("utf-8", errors="ignore")
        geo = {}
        for line in text.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                geo[k.strip()] = v.strip()
        return geo
    except Exception:
        return {}


class ShodanScanner:
    def scan(self, target: str) -> list[dict]:
        shodan_key = os.getenv("SHODAN_API_KEY", "")

        ip = target
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            pass

        ports       = []
        services    = []
        vulns       = []
        org         = ""
        isp         = ""
        os_info     = ""
        hostnames   = []
        data_source = "free-apis"
        tags        = []
        raw_services= {}

        # 1. Official Shodan API
        if shodan_key:
            sd = _shodan_official(ip, shodan_key)
            if sd:
                data_source = "shodan_api"
                ports     = sd.get("ports", [])
                org       = sd.get("org", "")
                isp       = sd.get("isp", "")
                os_info   = sd.get("os", "") or ""
                hostnames = sd.get("hostnames", [])
                vulns     = list(sd.get("vulns", {}).keys())
                tags      = sd.get("tags", [])
                for item in sd.get("data", []):
                    port = item.get("port")
                    if port:
                        services.append({
                            "port":    port,
                            "service": item.get("_shodan", {}).get("module", "unknown"),
                            "banner":  str(item.get("data", ""))[:200],
                            "product": item.get("product", ""),
                            "version": item.get("version", ""),
                        })

        # 2. BGPView for ASN (always free)
        bgp = _bgpview_asn(ip)

        # 3. HackerTarget for open ports (if no Shodan)
        if not shodan_key:
            ht_ports = _hackertarget_ports(ip)
            if ht_ports:
                ports = ht_ports
                data_source = "hackertarget+bgpview"

        # 4. GeoIP from HackerTarget
        geo = _hackertarget_geo(ip)

        result = {
            "target":      target,
            "ip":          ip,
            "data_source": data_source,
            "org":         org or (bgp.get("asn_description", "") if bgp else ""),
            "isp":         isp,
            "os":          os_info,
            "hostnames":   hostnames,
            "open_ports":  ports,
            "services":    services[:20],
            "vulns":       vulns,
            "tags":        tags,
            "asn": bgp or {},
            "geo": {
                "country": geo.get("Country", ""),
                "city":    geo.get("City", ""),
                "lat":     geo.get("Latitude", ""),
                "lon":     geo.get("Longitude", ""),
            },
            "note": "" if shodan_key else "Set SHODAN_API_KEY for full data. Free: BGPView ASN + HackerTarget ports.",
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        return [result]
