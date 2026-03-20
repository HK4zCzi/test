"""
WHOIS Scanner — Dùng WhoisXML API làm ưu tiên số 1, fallback về python-whois và whois CLI.
Tích hợp cơ chế kiểm tra dữ liệu thật, chống "Pass ảo" (False Positive).
"""
import subprocess
import logging
import requests
import os
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

def _parse_date(val) -> str:
    if not val:
        return ""
    if isinstance(val, list):
        val = val[0]
    try:
        return val.strftime("%Y-%m-%dT%H:%M:%SZ") if hasattr(val, "strftime") else str(val)
    except Exception:
        return str(val)


class WHOISScanner:
    def __init__(self, api_key: str = None):
        # Tự động lấy key từ biến môi trường nếu không được truyền vào
        self.api_key = api_key or os.getenv("WHOISXML_API_KEY")

    def scan(self, domain: str) -> list[dict]:
        result = None

        # --- Lớp 1: Gọi API (Ưu tiên cao nhất) ---
        if self.api_key:
            logger.info("Đang thử lấy WHOIS qua API WhoisXML cho %s", domain)
            result = self._api_whois(domain)

        # --- Lớp 2: Fallback dùng thư viện python-whois ---
        if not self._is_valid(result):
            logger.info("API thất bại hoặc không có Key, chuyển sang python-whois cho %s", domain)
            result = self._python_whois(domain)

        # --- Lớp 3: Fallback dùng lệnh CLI hệ thống ---
        if not self._is_valid(result):
            logger.warning("python-whois không lấy được dữ liệu, thử dùng CLI cho %s", domain)
            result = self._cli_whois(domain)

        # --- Chốt chặn cuối cùng ---
        if not self._is_valid(result):
            raise ValueError(f"WHOIS lookup failed: Không thể lấy dữ liệu hợp lệ cho {domain} qua bất kỳ cách nào.")

        return [result]

    def _is_valid(self, result: dict) -> bool:
        """Hàm kiểm tra xem kết quả có rỗng (Pass ảo) hay không"""
        if not result:
            return False
        
        # Nếu không có Registrar (Nhà đăng ký) VÀ không có Name Server thì coi như vô giá trị
        registrar = result.get("registrar")
        name_servers = result.get("name_servers")
        
        if not registrar and not name_servers:
            return False
            
        return True

    def _api_whois(self, domain: str) -> dict:
        """Lấy dữ liệu chuẩn xác từ WhoisXML API"""
        try:
            url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={self.api_key}&domainName={domain}&outputFormat=JSON"
            response = requests.get(url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                record = data.get("WhoisRecord", {})
                
                # Nếu API trả về lỗi dữ liệu (tên miền không tồn tại)
                if "dataError" in record or not record.get("registrarName"):
                    return None
                
                ns_data = record.get("nameServers", {}).get("hostNames", [])
                
                # Format status
                raw_status = record.get("status", "")
                status_list = raw_status.split(" ") if isinstance(raw_status, str) else raw_status
                
                return {
                    "domain": domain,
                    "registrar": str(record.get("registrarName", "")),
                    "creation_date": _parse_date(record.get("createdDate")),
                    "expiration_date": _parse_date(record.get("expiresDate")),
                    "updated_date": _parse_date(record.get("updatedDate")),
                    "name_servers": ns_data,
                    "status": status_list,
                    "emails": [record.get("contactEmail")] if record.get("contactEmail") else [],
                    "org": str(record.get("registrant", {}).get("organization", "")),
                    "country": str(record.get("registrant", {}).get("country", "")),
                    "dnssec": "", 
                    "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                }
        except Exception as e:
            logger.warning("WhoisXML API Exception: %s", e)
        return None

    def _python_whois(self, domain: str) -> dict:
        """Dùng thư viện python-whois cục bộ"""
        try:
            import whois
            w = whois.whois(domain)
            
            ns = w.name_servers or []
            status = w.status or []
            emails = w.emails or []

            return {
                "domain": domain,
                "registrar": str(w.registrar or "").strip(),
                "creation_date": _parse_date(w.creation_date),
                "expiration_date": _parse_date(w.expiration_date),
                "updated_date": _parse_date(w.updated_date),
                "name_servers": [str(n).lower() for n in (ns if isinstance(ns, list) else [ns]) if n],
                "status": [str(s) for s in (status if isinstance(status, list) else [status]) if s],
                "emails": [str(e) for e in (emails if isinstance(emails, list) else [emails]) if e],
                "org": str(w.org or "").strip(),
                "country": str(w.country or "").strip(),
                "dnssec": str(w.dnssec or "").strip(),
                "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        except ImportError:
            logger.error("Thư viện 'python-whois' chưa được cài (pip install python-whois)")
            return None
        except Exception as e:
            logger.warning("python-whois Exception: %s", e)
            return None

    def _cli_whois(self, domain: str) -> dict:
        """Dùng lệnh hệ thống (CLI) làm phương án cuối cùng"""
        try:
            result = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=20)
            raw = result.stdout

            # Bắt lỗi nếu máy chủ whois không trả về gì hoặc không biết tên miền
            if not raw or "No whois server is known" in raw or "No match for" in raw:
                return None

            def extract(field):
                for line in raw.splitlines():
                    ll = line.lower()
                    if ll.startswith(field.lower() + ":"):
                        return line.split(":", 1)[1].strip()
                return ""

            ns = extract("Name Server")
            domain_status = extract("Domain Status")

            return {
                "domain": domain,
                "registrar": extract("Registrar"),
                "creation_date": extract("Creation Date"),
                "expiration_date": extract("Registry Expiry Date"),
                "updated_date": extract("Updated Date"),
                "name_servers": [ns] if ns else [],
                "status": [domain_status] if domain_status else [],
                "emails": [],
                "org": extract("Registrant Organization"),
                "country": extract("Registrant Country"),
                "dnssec": extract("DNSSEC"),
                "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        except FileNotFoundError:
            logger.error("Lệnh 'whois' chưa được cài đặt trên máy. Hãy chạy: sudo apt install whois")
            return None
        except Exception as e:
            logger.warning("CLI WHOIS Exception: %s", e)
            return None
