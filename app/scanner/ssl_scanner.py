"""
SSL/TLS Scanner — dùng Python ssl module + openssl CLI để lấy đủ thông tin
"""
import ssl, socket, subprocess, re, logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def _grade(tls_ver: str, issues: list, days_left: int) -> str:
    if days_left < 0:
        return "F"
    if issues:
        severe = [i for i in issues if "expired" in i.lower() or "self-signed" in i.lower() or "weak" in i.lower()]
        if severe:
            return "C"
    if "1.3" in tls_ver:
        return "A"
    if "1.2" in tls_ver:
        return "B"
    return "C"


class SSLScanner:
    def scan(self, domain: str, port: int = 443) -> list[dict]:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=10) as raw:
                with ctx.wrap_socket(raw, server_hostname=domain) as ssl_sock:
                    cert = ssl_sock.getpeercert()
                    tls_version = ssl_sock.version() or "unknown"
                    cipher = ssl_sock.cipher()
                    cipher_name = cipher[0] if cipher else "unknown"

            # Parse dates
            fmt = "%b %d %H:%M:%S %Y %Z"
            not_before_str = cert.get("notBefore", "")
            not_after_str  = cert.get("notAfter", "")
            try:
                from datetime import datetime as dt
                valid_from  = dt.strptime(not_before_str, fmt).replace(tzinfo=timezone.utc)
                valid_until = dt.strptime(not_after_str, fmt).replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (valid_until - now).days
                is_expired = days_left < 0
            except Exception:
                valid_from = valid_until = datetime.now(timezone.utc)
                days_left = 0
                is_expired = False

            # SANs
            san_list = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

            # Subject & issuer
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer  = dict(x[0] for x in cert.get("issuer", []))
            is_self_signed = subject == issuer

            issues = []
            if is_expired:
                issues.append("Certificate is expired")
            elif days_left < 30:
                issues.append(f"Expires soon: {days_left} days left")
            if is_self_signed:
                issues.append("Self-signed certificate")
            if "TLS 1.0" in tls_version or "TLS 1.1" in tls_version:
                issues.append(f"Weak TLS version: {tls_version}")

            grade = _grade(tls_version, issues, days_left)

            result = {
                "domain": domain,
                "certificate": {
                    "subject":          f"CN={subject.get('commonName', domain)}",
                    "issuer":           f"O={issuer.get('organizationName', '')}",
                    "serial_number":    cert.get("serialNumber", ""),
                    "valid_from":       valid_from.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "valid_until":      valid_until.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "days_until_expiry": days_left,
                    "is_expired":       is_expired,
                    "is_self_signed":   is_self_signed,
                    "san":              san_list,
                },
                "connection": {
                    "tls_version":  tls_version,
                    "cipher_suite": cipher_name,
                },
                "grade":  grade,
                "issues": issues,
                "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            return [result]

        except ssl.SSLError as e:
            raise ValueError(f"SSL error: {e}") from e
        except Exception as e:
            logger.error("SSLScanner error for %s: %s", domain, e)
            raise
