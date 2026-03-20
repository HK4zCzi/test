"""
Bài 2: Unit Tests cho Scan API (day3)
Covers: 2.1 Model tests, 2.4 Scanner tests
"""
import pytest
from unittest.mock import patch, MagicMock
from app.domain.scan import (
    ScanType, ScanStatus, ScanJob,
    DOMAIN_ONLY_SCANS, IP_ONLY_SCANS,
)


# ── 2.1 Scan Domain Model Tests ────────────────────────────────────
class TestScanType:
    def test_all_domain_scan_types_valid(self):
        for v in ["dns","whois","subdomain","cert_trans","ssl","tech",
                  "headers","waf","takeover","gau","virustotal","urlscan",
                  "js_scan","cors","s3","dir_brute","http_probe",
                  "xss","ssrf","crlf"]:
            assert ScanType(v).value == v

    def test_all_ip_scan_types_valid(self):
        for v in ["ip","asn","reverse_dns","shodan","port"]:
            assert ScanType(v).value == v

    def test_invalid_scan_type_raises(self):
        with pytest.raises(ValueError):
            ScanType("nmap_aggressive")

    def test_domain_only_set_correct(self):
        assert ScanType.dns in DOMAIN_ONLY_SCANS
        assert ScanType.ssl in DOMAIN_ONLY_SCANS
        assert ScanType.xss in DOMAIN_ONLY_SCANS
        # IP types must NOT be in domain set
        assert ScanType.ip not in DOMAIN_ONLY_SCANS
        assert ScanType.port not in DOMAIN_ONLY_SCANS
        assert ScanType.shodan not in DOMAIN_ONLY_SCANS

    def test_ip_only_set_correct(self):
        assert ScanType.ip in IP_ONLY_SCANS
        assert ScanType.shodan in IP_ONLY_SCANS
        assert ScanType.port in IP_ONLY_SCANS
        # Domain types must NOT be in IP set
        assert ScanType.dns not in IP_ONLY_SCANS
        assert ScanType.ssl not in IP_ONLY_SCANS

    def test_no_overlap_between_sets(self):
        overlap = DOMAIN_ONLY_SCANS & IP_ONLY_SCANS
        assert len(overlap) == 0, f"Overlap found: {overlap}"


class TestScanJob:
    def test_scan_job_defaults(self):
        job = ScanJob(
            id="abc", asset_id="def",
            scan_type=ScanType.dns, created_at="2026-01-01T00:00:00Z"
        )
        assert job.status == ScanStatus.pending
        assert job.error == ""
        assert job.results == 0
        assert job.started_at is None
        assert job.ended_at is None

    def test_all_status_values(self):
        for v in ["pending","running","completed","failed","partial"]:
            assert ScanStatus(v).value == v


# ── 2.4 Scanner Unit Tests ─────────────────────────────────────────
class TestPortScannerSafety:
    def test_localhost_is_private(self):
        from app.scanner.port_scanner import _is_private_ip
        assert _is_private_ip("127.0.0.1") is True

    def test_private_ranges(self):
        from app.scanner.port_scanner import _is_private_ip
        for ip in ["10.0.0.1","192.168.1.100","172.16.0.1","172.31.255.255"]:
            assert _is_private_ip(ip) is True, f"{ip} should be private"

    def test_public_ips_not_private(self):
        from app.scanner.port_scanner import _is_private_ip
        for ip in ["8.8.8.8","1.1.1.1","142.250.80.46"]:
            assert _is_private_ip(ip) is False, f"{ip} should be public"

    def test_public_scan_allowed_with_flag(self):
        from app.scanner.port_scanner import PortScanner
        scanner = PortScanner()
        # Should not raise when allow_public=True
        with patch("app.scanner.port_scanner._nmap_scan", return_value=[]):
            with patch("app.scanner.port_scanner._socket_scan", return_value=[]):
                result = scanner.scan("8.8.8.8", allow_public=True)
                assert isinstance(result, list)
                assert result[0]["disclaimer"] != ""

    def test_public_scan_blocked_by_default(self):
        from app.scanner.port_scanner import PortScanner
        scanner = PortScanner()
        with pytest.raises(ValueError, match="allow_public"):
            scanner.scan("8.8.8.8", allow_public=False)


class TestIPScanner:
    @patch("app.scanner.ip_scanner.urllib.request.urlopen")
    def test_ipapi_co_success(self, mock_open):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'''{
            "country_name":"United States","country_code":"US",
            "city":"Mountain View","region":"California",
            "latitude":37.4,"longitude":-122.1,
            "org":"AS15169 Google LLC","asn":"AS15169"
        }'''
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_open.return_value = mock_resp

        from app.scanner.ip_scanner import IPScanner
        results = IPScanner().scan("8.8.8.8")
        assert len(results) == 1
        assert results[0]["geolocation"]["country"] == "United States"
        assert results[0]["asn"]["number"] == 15169

    @patch("app.scanner.ip_scanner.urllib.request.urlopen")
    def test_all_apis_fail_raises(self, mock_open):
        mock_open.side_effect = Exception("network error")
        from app.scanner.ip_scanner import IPScanner
        with pytest.raises(ValueError, match="All geo APIs failed"):
            IPScanner().scan("8.8.8.8")


class TestSSLScanner:
    @patch("ssl.create_default_context")
    @patch("socket.create_connection")
    def test_ssl_result_structure(self, mock_conn, mock_ctx):
        mock_ssl = MagicMock()
        mock_ssl.version.return_value = "TLSv1.3"
        mock_ssl.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssl.getpeercert.return_value = {
            "subject": [[("commonName", "example.com")]],
            "issuer":  [[("commonName", "Let's Encrypt"), ("organizationName", "LE")]],
            "serialNumber": "ABCDEF",
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter":  "Apr  1 00:00:00 2026 GMT",
            "subjectAltName": [("DNS","example.com"),("DNS","www.example.com")],
        }
        mock_ssl.__enter__ = lambda s: s
        mock_ssl.__exit__ = MagicMock(return_value=False)
        mock_raw = MagicMock()
        mock_raw.__enter__ = lambda s: s
        mock_raw.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_raw
        mock_ctx.return_value.wrap_socket.return_value = mock_ssl

        from app.scanner.ssl_scanner import SSLScanner
        results = SSLScanner().scan("example.com")
        assert len(results) == 1
        r = results[0]
        assert r["grade"] in ("A","B","C","D","F")
        assert "certificate" in r
        assert "san" in r["certificate"]
        assert "example.com" in r["certificate"]["san"]
        assert r["certificate"]["days_until_expiry"] > 0


class TestWAFScanner:
    @patch("app.scanner.waf_scanner._wafw00f_scan")
    @patch("app.scanner.waf_scanner._get_subdomains")
    def test_cloudflare_detected(self, mock_subs, mock_wafw00f):
        mock_subs.return_value = []
        mock_wafw00f.return_value = {"detected": True, "waf": "Cloudflare", "manufacturer": "Cloudflare Inc."}

        from app.scanner.waf_scanner import WAFScanner
        results = WAFScanner().scan("example.com", scan_subdomains=False)
        assert results[0]["waf_detected"] is True
        assert results[0]["waf_name"] == "Cloudflare"

    @patch("app.scanner.waf_scanner._wafw00f_scan")
    @patch("app.scanner.waf_scanner._get_subdomains")
    def test_no_waf_detected(self, mock_subs, mock_wafw00f):
        mock_subs.return_value = []
        mock_wafw00f.return_value = {"detected": False, "waf": None, "manufacturer": None}

        from app.scanner.waf_scanner import WAFScanner
        results = WAFScanner().scan("example.com", scan_subdomains=False)
        assert results[0]["waf_detected"] is False
        assert results[0]["waf_name"] is None


class TestDNSScanner:
    @patch("app.scanner.dns_scanner._dnspython_lookup")
    @patch("app.scanner.dns_scanner._dig_lookup")
    def test_dns_returns_records(self, mock_dig, mock_dnspy):
        mock_dnspy.return_value = {
            "A": ["93.184.216.34"],
            "NS": ["ns1.example.com."],
            "MX": ["0 mail.example.com."],
        }
        mock_dig.return_value = []

        from app.scanner.dns_scanner import DNSScanner
        results = DNSScanner().scan("example.com")
        assert results[0]["total_records"] == 3
        assert "A" in results[0]["records"]

    @patch("app.scanner.dns_scanner._dnspython_lookup")
    @patch("app.scanner.dns_scanner._dig_lookup")
    def test_empty_domain_returns_empty(self, mock_dig, mock_dnspy):
        mock_dnspy.return_value = {}
        mock_dig.return_value = []
        from app.scanner.dns_scanner import DNSScanner
        results = DNSScanner().scan("nonexistent.invalid")
        assert results[0]["total_records"] == 0


class TestVulnScanners:
    def test_xss_scanner_result_structure(self):
        from app.scanner.vuln_scanner import XSSScanner
        with patch("app.scanner.vuln_scanner._test_xss_param", return_value=None):
            results = XSSScanner().scan("example.com")
        r = results[0]
        assert "domain" in r
        assert "findings" in r
        assert "vulnerable" in r
        assert "disclaimer" in r
        assert r["vulnerable"] is False

    def test_ssrf_scanner_result_structure(self):
        from app.scanner.vuln_scanner import SSRFScanner
        with patch("app.scanner.vuln_scanner._test_ssrf_param", return_value=None):
            results = SSRFScanner().scan("example.com")
        assert results[0]["type"] == "ssrf"
        assert isinstance(results[0]["findings"], list)

    def test_crlf_scanner_result_structure(self):
        from app.scanner.vuln_scanner import CRLFScanner
        with patch("app.scanner.vuln_scanner._test_crlf", return_value=None):
            results = CRLFScanner().scan("example.com")
        assert results[0]["type"] == "crlf"

    def test_xss_finding_detected(self):
        from app.scanner.vuln_scanner import XSSScanner
        fake_finding = {
            "url": "https://example.com?q=<script>",
            "param": "q",
            "payload": "<script>alert(1)</script>",
            "type": "Reflected XSS",
            "evidence": "Pattern found",
            "severity": "high",
        }
        with patch("app.scanner.vuln_scanner._test_xss_param", return_value=fake_finding):
            results = XSSScanner().scan("example.com")
        assert results[0]["vulnerable"] is True
        assert len(results[0]["findings"]) > 0
