"""
Unit tests for scanner modules — Bài 2.4
Tests safety logic, input validation, and result structure
Updated to match refactored scanner API
"""
import pytest
from unittest.mock import patch, MagicMock
from app.scanner.port_scanner import PortScanner, _is_private_ip
from app.scanner.ip_scanner import IPScanner
from app.scanner.ssl_scanner import SSLScanner
from app.scanner.tech_scanner import TechScanner


# ── Port Scanner Tests ────────────────────────────────────────────────
class TestPortScannerSafety:
    """Critical: ensure port scanner safety checks work correctly"""

    def test_localhost_is_allowed(self):
        assert _is_private_ip("127.0.0.1") is True

    def test_private_10_range_allowed(self):
        assert _is_private_ip("10.0.0.1") is True
        assert _is_private_ip("10.255.255.255") is True

    def test_private_192168_range_allowed(self):
        assert _is_private_ip("192.168.1.100") is True

    def test_private_172_range_allowed(self):
        assert _is_private_ip("172.16.0.1") is True
        assert _is_private_ip("172.31.255.255") is True

    def test_public_ip_rejected(self):
        assert _is_private_ip("8.8.8.8") is False

    def test_cloudflare_rejected(self):
        assert _is_private_ip("1.1.1.1") is False

    def test_google_rejected(self):
        assert _is_private_ip("142.250.80.46") is False

    def test_scan_public_ip_blocked_by_default(self):
        """Public IP scan is blocked when allow_public=False (default)"""
        scanner = PortScanner()
        with pytest.raises(ValueError):
            scanner.scan("8.8.8.8", allow_public=False)

    def test_scan_public_ip_allowed_with_flag(self):
        """Public IP scan is allowed when allow_public=True"""
        scanner = PortScanner()
        # Mock both scan methods to avoid real network calls
        with patch("app.scanner.port_scanner._nmap_scan", return_value=[]):
            with patch("app.scanner.port_scanner._socket_scan", return_value=[]):
                results = scanner.scan("8.8.8.8", allow_public=True)
        assert isinstance(results, list)
        assert len(results) == 1
        assert results[0]["is_private"] is False

    def test_scan_localhost_returns_structure(self):
        """Mock nmap/socket to verify result structure"""
        mock_ports = [
            {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": ""},
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": ""},
        ]
        with patch("app.scanner.port_scanner._nmap_scan", return_value=mock_ports):
            scanner = PortScanner()
            results = scanner.scan("127.0.0.1")

        assert isinstance(results, list)
        assert len(results) == 1
        result = results[0]
        assert "ip_address" in result
        assert "open_ports" in result
        assert "closed_ports" in result
        assert "total_scanned" in result
        assert "scan_duration_ms" in result
        assert result["is_private"] is True
        assert len(result["open_ports"]) == 2


# ── IP Scanner Tests ──────────────────────────────────────────────────
class TestIPScanner:
    """Test IP scanner result structure — uses ipapi.co as primary API"""

    @patch("app.scanner.ip_scanner.urllib.request.urlopen")
    def test_scan_returns_correct_structure(self, mock_urlopen):
        """Mock ipapi.co response (primary API in new ip_scanner)"""
        mock_resp = MagicMock()
        # ipapi.co JSON format (new primary API)
        mock_resp.read.return_value = b'''{
            "country_name": "United States",
            "country_code": "US",
            "region": "California",
            "city": "San Francisco",
            "latitude": 37.7749,
            "longitude": -122.4194,
            "org": "AS13335 Cloudflare, Inc.",
            "asn": "AS13335"
        }'''
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        scanner = IPScanner()
        results = scanner.scan("1.1.1.1")

        assert len(results) == 1
        result = results[0]
        assert "ip_address" in result
        assert "geolocation" in result
        assert "asn" in result
        assert "reverse_dns" in result
        assert "created_at" in result

        geo = result["geolocation"]
        assert geo["country"] == "United States"
        assert geo["country_code"] == "US"
        assert geo["city"] == "San Francisco"

        asn = result["asn"]
        assert asn["number"] == 13335

    @patch("app.scanner.ip_scanner.urllib.request.urlopen")
    def test_scan_all_apis_fail_raises(self, mock_urlopen):
        """When all geo APIs fail, should raise ValueError"""
        mock_urlopen.side_effect = Exception("network error")

        scanner = IPScanner()
        with pytest.raises(ValueError, match="All geo APIs failed"):
            scanner.scan("1.1.1.1")


# ── SSL Scanner Tests ─────────────────────────────────────────────────
class TestSSLScanner:
    """Test SSL scanner result structure"""

    @patch("ssl.create_default_context")
    @patch("socket.create_connection")
    def test_scan_returns_correct_structure(self, mock_conn, mock_ctx):
        """Mock SSL connection"""
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.version.return_value = "TLSv1.3"
        mock_ssl_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssl_sock.getpeercert.return_value = {
            "subject": [[("commonName", "example.com")]],
            "issuer": [[("commonName", "Let's Encrypt"), ("organizationName", "Let's Encrypt")]],
            "serialNumber": "03ABCDEF",
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Apr  1 00:00:00 2026 GMT",
            "subjectAltName": [("DNS", "example.com"), ("DNS", "www.example.com")],
        }
        mock_ssl_sock.__enter__ = lambda s: s
        mock_ssl_sock.__exit__ = MagicMock(return_value=False)
        mock_raw_sock = MagicMock()
        mock_raw_sock.__enter__ = lambda s: s
        mock_raw_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_raw_sock
        mock_context = MagicMock()
        mock_context.wrap_socket.return_value = mock_ssl_sock
        mock_ctx.return_value = mock_context

        scanner = SSLScanner()
        results = scanner.scan("example.com")

        assert len(results) == 1
        result = results[0]
        assert "domain" in result
        assert "certificate" in result
        assert "connection" in result
        assert "grade" in result
        assert "issues" in result

        cert = result["certificate"]
        assert "subject" in cert
        assert "issuer" in cert
        assert "valid_from" in cert
        assert "valid_until" in cert
        assert "days_until_expiry" in cert
        assert "san" in cert
        assert "example.com" in cert["san"]


# ── Tech Scanner Tests ────────────────────────────────────────────────
class TestTechScanner:
    """Test technology detection scanner — uses requests library"""

    @patch("app.scanner.tech_scanner.requests")
    def test_detects_nginx(self, mock_requests):
        """Mock requests.get (tech_scanner uses requests, not urllib)"""
        mock_resp = MagicMock()
        mock_resp.headers = {"server": "nginx/1.18.0", "content-type": "text/html"}
        mock_resp.text = "<html><head></head><body>Hello</body></html>"
        mock_resp.status_code = 200
        mock_requests.get.return_value = mock_resp

        scanner = TechScanner()
        results = scanner.scan("example.com")

        assert len(results) == 1
        result = results[0]
        assert "technologies" in result
        assert "headers" in result
        assert "meta_tags" in result

        tech_names = [t["name"] for t in result["technologies"]]
        assert "nginx" in tech_names

    @patch("app.scanner.tech_scanner.requests")
    def test_detects_php(self, mock_requests):
        """Test PHP detection via x-powered-by header"""
        mock_resp = MagicMock()
        mock_resp.headers = {
            "server": "Apache/2.4.51",
            "x-powered-by": "PHP/8.1.0",
            "content-type": "text/html",
        }
        mock_resp.text = "<html></html>"
        mock_resp.status_code = 200
        mock_requests.get.return_value = mock_resp

        scanner = TechScanner()
        results = scanner.scan("example.com")

        assert results[0]["domain"] == "example.com"
        assert isinstance(results[0]["technologies"], list)
        assert isinstance(results[0]["headers"], dict)
        tech_names = [t["name"] for t in results[0]["technologies"]]
        assert "PHP" in tech_names

    @patch("app.scanner.tech_scanner.requests")
    def test_result_structure(self, mock_requests):
        """Verify result has all required keys"""
        mock_resp = MagicMock()
        mock_resp.headers = {"server": "Apache/2.4.51", "content-type": "text/html"}
        mock_resp.text = "<html></html>"
        mock_resp.status_code = 200
        mock_requests.get.return_value = mock_resp

        scanner = TechScanner()
        results = scanner.scan("example.com")

        assert results[0]["domain"] == "example.com"
        assert isinstance(results[0]["technologies"], list)
        assert isinstance(results[0]["headers"], dict)
        assert "created_at" in results[0]
