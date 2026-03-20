"""
HTTP Probe Scanner — alive check, title, redirect chain, response time
Dùng requests để handle redirects đúng cách
"""
import re, time, logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class HTTPProbeScanner:
    def scan(self, target: str) -> list[dict]:
        import requests

        probes = []
        for scheme in ("https", "http"):
            url = f"{scheme}://{target}"
            start = time.time()
            try:
                resp = requests.get(
                    url,
                    headers={"User-Agent": "Mozilla/5.0 EASM-Scanner/1.0"},
                    timeout=10,
                    allow_redirects=True,
                    verify=False,
                )
                elapsed = int((time.time() - start) * 1000)
                body = resp.text[:16384]

                # Extract title
                title = ""
                m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                if m:
                    title = re.sub(r'\s+', ' ', m.group(1)).strip()[:120]

                # Redirect chain
                redirect_chain = [r.url for r in resp.history] + [resp.url]

                probes.append({
                    "url": url,
                    "final_url": resp.url,
                    "status_code": resp.status_code,
                    "alive": True,
                    "response_time_ms": elapsed,
                    "title": title,
                    "server": resp.headers.get("server", ""),
                    "content_type": resp.headers.get("content-type", ""),
                    "content_length": len(body),
                    "redirect_chain": redirect_chain,
                    "cookies": list(resp.cookies.keys()),
                })
            except requests.exceptions.SSLError as e:
                probes.append({
                    "url": url, "final_url": url, "status_code": 0,
                    "alive": False, "response_time_ms": int((time.time()-start)*1000),
                    "title": "", "server": "", "content_type": "",
                    "content_length": 0, "redirect_chain": [], "cookies": [],
                    "error": f"SSL error: {str(e)[:100]}",
                })
            except Exception as e:
                probes.append({
                    "url": url, "final_url": url, "status_code": 0,
                    "alive": False, "response_time_ms": int((time.time()-start)*1000),
                    "title": "", "server": "", "content_type": "",
                    "content_length": 0, "redirect_chain": [], "cookies": [],
                    "error": str(e)[:100],
                })

        return [{
            "target": target,
            "probes": probes,
            "alive": any(p["alive"] for p in probes),
            "https_available": any(p["alive"] and p["url"].startswith("https") for p in probes),
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }]
