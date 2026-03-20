"""
JS Scanner — tìm JS files, extract endpoints + secrets (API keys, tokens)
Tương đương: linkfinder, secretfinder, getJS
"""
import re
import logging
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

# Secret patterns to find in JS files
SECRET_PATTERNS = [
    {"name": "AWS Access Key",       "pattern": r"AKIA[0-9A-Z]{16}"},
    {"name": "AWS Secret",           "pattern": r"aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"},
    {"name": "Generic API Key",      "pattern": r"api[_-]?key['\"\s:=]+['\"][a-zA-Z0-9_\-]{16,45}['\"]"},
    {"name": "Generic Token",        "pattern": r"token['\"\s:=]+['\"][a-zA-Z0-9_\-\.]{20,60}['\"]"},
    {"name": "Bearer Token",         "pattern": r"Bearer\s+[a-zA-Z0-9_\-\.]{20,}"},
    {"name": "Google API Key",       "pattern": r"AIza[0-9A-Za-z\-_]{35}"},
    {"name": "Firebase",             "pattern": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"},
    {"name": "Slack Token",          "pattern": r"xox[baprs]-([0-9a-zA-Z]{10,48})?"},
    {"name": "GitHub Token",         "pattern": r"ghp_[0-9a-zA-Z]{36}"},
    {"name": "Stripe Key",           "pattern": r"sk_live_[0-9a-zA-Z]{24}"},
    {"name": "Password in JS",       "pattern": r"password['\"\s:=]+['\"][^'\"]{6,30}['\"]"},
    {"name": "Private Key",          "pattern": r"-----BEGIN.{0,10}PRIVATE KEY-----"},
    {"name": "JWT",                  "pattern": r"eyJ[a-zA-Z0-9]{10,}\.[a-zA-Z0-9]{10,}\.[a-zA-Z0-9_-]{10,}"},
]

# Endpoint patterns
ENDPOINT_PATTERNS = [
    r"""['"`](\/?(?:api|v\d|rest|graphql)[a-zA-Z0-9_\-\/\.]*(?:\?[a-zA-Z0-9_\-=&]*)?)['"`]""",
    r"""['"`](\/[a-zA-Z0-9_\-]{2,50}(?:\/[a-zA-Z0-9_\-]{2,50})+(?:\?[a-zA-Z0-9_\-=&]*)?)['"`]""",
    r"""(?:fetch|axios\.(?:get|post|put|delete)|XMLHttpRequest)\s*\(\s*['"`]([^'"`]+)['"`]""",
    r"""(?:url|endpoint|path|route)\s*[:=]\s*['"`]([^'"`\s]{5,100})['"`]""",
]


def _find_js_files(domain: str) -> list[str]:
    """Find JS files from homepage HTML"""
    try:
        import requests
        resp = requests.get(
            f"https://{domain}",
            headers={"User-Agent": "Mozilla/5.0 EASM-Scanner/1.0"},
            timeout=10, verify=False, allow_redirects=True
        )
        html = resp.text
        # Find JS file references
        js_urls = re.findall(r'src=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', html, re.IGNORECASE)
        abs_urls = []
        for u in js_urls:
            if u.startswith("http"):
                abs_urls.append(u)
            elif u.startswith("//"):
                abs_urls.append("https:" + u)
            elif u.startswith("/"):
                abs_urls.append(f"https://{domain}{u}")
            else:
                abs_urls.append(f"https://{domain}/{u}")
        return list(set(abs_urls))[:20]  # cap at 20 JS files
    except Exception as e:
        logger.warning("Finding JS files failed for %s: %s", domain, e)
        return []


def _scan_js_file(url: str) -> dict:
    """Download and scan one JS file"""
    try:
        import requests
        resp = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0 EASM-Scanner/1.0"},
            timeout=10, verify=False
        )
        content = resp.text[:500000]  # 500KB max

        # Find secrets
        secrets_found = []
        for secret_def in SECRET_PATTERNS:
            matches = re.findall(secret_def["pattern"], content, re.IGNORECASE)
            for match in matches[:3]:  # max 3 per pattern
                match_str = match if isinstance(match, str) else match[0] if match else ""
                if len(match_str) > 5:
                    secrets_found.append({
                        "type":  secret_def["name"],
                        "match": match_str[:80] + "..." if len(match_str) > 80 else match_str,
                    })

        # Find endpoints
        endpoints_found = set()
        for pattern in ENDPOINT_PATTERNS:
            matches = re.findall(pattern, content)
            for m in matches[:20]:
                ep = m if isinstance(m, str) else m[0] if m else ""
                if ep and len(ep) > 3 and not ep.endswith((".js", ".css", ".png", ".jpg")):
                    endpoints_found.add(ep)

        return {
            "url":       url,
            "size_kb":   round(len(content) / 1024, 1),
            "secrets":   secrets_found,
            "endpoints": list(endpoints_found)[:30],
        }
    except Exception as e:
        return {"url": url, "error": str(e)[:80], "secrets": [], "endpoints": []}


class JSScanner:
    """JS files analysis — endpoints + secrets extraction"""

    def scan(self, domain: str) -> list[dict]:
        js_files = _find_js_files(domain)
        if not js_files:
            return [{
                "domain":       domain,
                "js_files":     0,
                "all_secrets":  [],
                "all_endpoints":[],
                "files":        [],
                "note":         "No JS files found",
                "created_at":   datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }]

        file_results = []
        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = {ex.submit(_scan_js_file, url): url for url in js_files}
            for future in as_completed(futures, timeout=60):
                try:
                    file_results.append(future.result())
                except Exception:
                    pass

        # Aggregate
        all_secrets   = []
        all_endpoints = set()
        for fr in file_results:
            all_secrets.extend(fr.get("secrets", []))
            all_endpoints.update(fr.get("endpoints", []))

        result = {
            "domain":        domain,
            "js_files":      len(js_files),
            "files_scanned": len(file_results),
            "secrets_found": len(all_secrets),
            "endpoints_found": len(all_endpoints),
            "all_secrets":   all_secrets[:50],
            "all_endpoints": sorted(all_endpoints)[:100],
            "files":         file_results,
            "created_at":    datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        return [result]
