"""
Unit tests for domain models — Bài 2.1
Tests asset validation, enum values, and scan domain models
"""
import pytest
from pydantic import ValidationError
from app.domain.asset import Asset, AssetType, AssetStatus, AssetStats
from app.domain.scan import ScanType, ScanStatus, ScanJob


class TestAssetValidation:
    """Test Asset entity validation"""

    def test_valid_domain_asset(self):
        asset = Asset(name="example.com", type="domain")
        assert asset.name == "example.com"
        assert asset.type == AssetType.domain
        assert asset.status == AssetStatus.active   # default

    def test_valid_ip_asset(self):
        asset = Asset(name="192.168.1.1", type="ip")
        assert asset.type == AssetType.ip

    def test_valid_service_asset(self):
        asset = Asset(name="my-service", type="service")
        assert asset.type == AssetType.service

    def test_invalid_type_raises(self):
        with pytest.raises(ValidationError):
            Asset(name="test.com", type="invalid_type")

    def test_empty_name_raises(self):
        with pytest.raises(ValidationError):
            Asset(name="", type="domain")

    def test_whitespace_only_name_raises(self):
        with pytest.raises(ValidationError):
            Asset(name="   ", type="domain")

    def test_name_too_long_raises(self):
        with pytest.raises(ValidationError):
            Asset(name="a" * 256, type="domain")

    def test_name_exactly_255_chars_ok(self):
        asset = Asset(name="a" * 255, type="domain")
        assert len(asset.name) == 255

    def test_null_byte_in_name_raises(self):
        with pytest.raises(ValidationError):
            Asset(name="test\x00name", type="domain")

    def test_status_defaults_to_active(self):
        asset = Asset(name="test.com", type="domain")
        assert asset.status == AssetStatus.active

    def test_explicit_inactive_status(self):
        asset = Asset(name="test.com", type="domain", status="inactive")
        assert asset.status == AssetStatus.inactive

    def test_invalid_status_raises(self):
        with pytest.raises(ValidationError):
            Asset(name="test.com", type="domain", status="deleted")

    def test_name_is_stripped(self):
        asset = Asset(name="  example.com  ", type="domain")
        assert asset.name == "example.com"


class TestAssetType:
    """Test AssetType enum"""

    def test_all_valid_types(self):
        assert AssetType.domain == "domain"
        assert AssetType.ip == "ip"
        assert AssetType.service == "service"

    def test_enum_from_string(self):
        t = AssetType("domain")
        assert t == AssetType.domain


class TestAssetStats:
    """Test AssetStats model"""

    def test_stats_with_data(self):
        stats = AssetStats(
            total=150,
            by_type={"domain": 100, "ip": 40, "service": 10},
            by_status={"active": 120, "inactive": 30},
        )
        assert stats.total == 150
        assert stats.by_type["domain"] == 100
        assert stats.by_status["active"] == 120

    def test_empty_stats(self):
        stats = AssetStats(total=0, by_type={}, by_status={})
        assert stats.total == 0


class TestScanDomain:
    """Test Scan domain models"""

    def test_all_scan_types_valid(self):
        for v in ["dns", "whois", "subdomain", "cert_trans", "ssl", "tech", "ip", "port", "all"]:
            t = ScanType(v)
            assert t.value == v

    def test_invalid_scan_type_raises(self):
        with pytest.raises(ValueError):
            ScanType("nmap")

    def test_all_scan_statuses_valid(self):
        for v in ["pending", "running", "completed", "failed", "partial"]:
            s = ScanStatus(v)
            assert s.value == v

    def test_scan_job_model(self):
        job = ScanJob(
            id="abc-123",
            asset_id="asset-456",
            scan_type=ScanType.ip,
            status=ScanStatus.pending,
            started_at="2026-01-01T00:00:00Z",
            ended_at=None,
            error="",
            results=0,
            created_at="2026-01-01T00:00:00Z",
        )
        assert job.id == "abc-123"
        assert job.scan_type == ScanType.ip
        assert job.status == ScanStatus.pending
