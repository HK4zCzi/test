"""
Technology Detection — dùng requests library + header/body fingerprinting
"""
import re
import logging
import requests
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

TECH_SIGNATURES = [
    # Web servers
    {"name":"nginx",        "category":"Web Server",          "header":"server",          "pattern":r"nginx/?(\S+)?"},
    {"name":"Apache",       "category":"Web Server",          "header":"server",          "pattern":r"Apache/?(\S+)?"},
    {"name":"Caddy",        "category":"Web Server",          "header":"server",          "pattern":r"Caddy/?(\S+)?"},
    {"name":"IIS",          "category":"Web Server",          "header":"server",          "pattern":r"Microsoft-IIS/?(\S+)?"},
    {"name":"LiteSpeed",    "category":"Web Server",          "header":"server",          "pattern":r"LiteSpeed"},
    {"name":"OpenResty",    "category":"Web Server",          "header":"server",          "pattern":r"openresty/?(\S+)?"},
    # Frameworks
    {"name":"Express",      "category":"Web Framework",       "header":"x-powered-by",    "pattern":r"Express"},
    {"name":"PHP",          "category":"Language",            "header":"x-powered-by",    "pattern":r"PHP/?(\S+)?"},
    {"name":"ASP.NET",      "category":"Web Framework",       "header":"x-powered-by",    "pattern":r"ASP\.NET"},
    {"name":"Next.js",      "category":"Web Framework",       "header":"x-powered-by",    "pattern":r"Next\.js"},
    {"name":"Laravel",      "category":"Web Framework",       "header":"x-powered-by",    "pattern":r"Laravel"},
    # CDN / Security
    {"name":"Cloudflare",   "category":"CDN",                 "header":"server",          "pattern":r"cloudflare"},
    {"name":"Cloudflare",   "category":"CDN",                 "header":"cf-ray",          "pattern":r".+"},
    {"name":"Fastly",       "category":"CDN",                 "header":"x-fastly-request-id","pattern":r".+"},
    {"name":"Varnish",      "category":"Cache",               "header":"x-varnish",       "pattern":r".+"},
    {"name":"Nginx",        "category":"Cache",               "header":"x-cache",         "pattern":r"HIT|MISS"},
    # Security headers (presence = tech indicator)
    {"name":"HSTS",         "category":"Security",            "header":"strict-transport-security","pattern":r".+"},
    {"name":"CSP",          "category":"Security",            "header":"content-security-policy","pattern":r".+"},
    # Body-based
    {"name":"React",        "category":"JS Framework",        "body":True, "pattern":r'react(?:\.min)?\.js|__NEXT_DATA__|react-root'},
    {"name":"Vue.js",       "category":"JS Framework",        "body":True, "pattern":r'vue(?:\.min)?\.js|data-v-'},
    {"name":"Angular",      "category":"JS Framework",        "body":True, "pattern":r'ng-version|angular(?:\.min)?\.js'},
    {"name":"jQuery",       "category":"JS Library",          "body":True, "pattern":r'jquery(?:\.min)?\.js'},
    {"name":"Bootstrap",    "category":"CSS Framework",       "body":True, "pattern":r'bootstrap(?:\.min)?\.css'},
    {"name":"WordPress",    "category":"CMS",                 "body":True, "pattern":r'wp-content|wp-includes|wordpress'},
    {"name":"Drupal",       "category":"CMS",                 "body":True, "pattern":r'drupal\.js|Drupal\.settings'},
    {"name":"Joomla",       "category":"CMS",                 "body":True, "pattern":r'/media/jui/|joomla'},
    {"name":"Shopify",      "category":"E-commerce",          "body":True, "pattern":r'cdn\.shopify\.com|Shopify\.theme'},
    {"name":"Google Analytics","category":"Analytics",        "body":True, "pattern":r'gtag\(|ga\.js|analytics\.js|googletagmanager'},
]


class TechScanner:
    def scan(self, domain: str) -> list[dict]:
        headers_found = {}
        body = ""

        for scheme in ("https", "http"):
            try:
                resp = requests.get(
                    f"{scheme}://{domain}",
                    headers={"User-Agent": "Mozilla/5.0 (compatible; EASM-Scanner/1.0)"},
                    timeout=12,
                    allow_redirects=True,
                    verify=False,
                )
                headers_found = {k.lower(): v for k, v in resp.headers.items()}
                body = resp.text[:65536]
                break
            except Exception as e:
                logger.debug("Tech scan %s %s failed: %s", scheme, domain, e)
                continue

        if not headers_found and not body:
            raise ValueError(f"Cannot reach {domain}")

        body_lower = body.lower()
        detected: dict[str, dict] = {}

        for sig in TECH_SIGNATURES:
            name = sig["name"]
            if sig.get("body"):
                m = re.search(sig["pattern"], body_lower, re.IGNORECASE)
                if m and name not in detected:
                    detected[name] = {"name": name, "category": sig["category"],
                                      "version": None, "confidence": 75}
            else:
                hval = headers_found.get(sig["header"], "")
                m = re.search(sig["pattern"], hval, re.IGNORECASE)
                if m and name not in detected:
                    ver = (m.group(1) if m.lastindex and m.group(1) else None)
                    detected[name] = {"name": name, "category": sig["category"],
                                      "version": ver, "confidence": 100}

        # Extract meta tags
        meta_tags = {}
        for match in re.finditer(
            r'<meta\s+(?:name|property)=["\']([^"\']+)["\']\s+content=["\']([^"\']*)["\']',
            body, re.IGNORECASE
        ):
            meta_tags[match.group(1)] = match.group(2)

        # Surface interesting headers
        interesting = ["server","x-powered-by","content-type","x-frame-options",
                       "x-content-type-options","strict-transport-security",
                       "content-security-policy","x-generator","x-drupal-cache"]
        surface_headers = {h: headers_found[h] for h in interesting if h in headers_found}

        result = {
            "domain": domain,
            "technologies": list(detected.values()),
            "headers": surface_headers,
            "meta_tags": dict(list(meta_tags.items())[:10]),
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        return [result]
