"""Tests for CVE enrichment module."""

import pytest
from unittest.mock import patch, AsyncMock

from cybersec_cli.utils.cve_enrichment import (
    _coerce_to_cve_item,
    get_cves_for_service,
    add_cve_entry,
    enrich_service_with_live_data,
    init_cve_cache,
)


class TestCoerceToCveItem:
    """Test the _coerce_to_cve_item helper function."""

    def test_passthrough_valid_dict(self):
        """Dict with id field should pass through unchanged (with normalization)."""
        d = {"id": "CVE-2024-1234", "severity": "HIGH", "cvss": 9.0}
        result = _coerce_to_cve_item(d)
        assert result is not None
        assert result["id"] == "CVE-2024-1234"
        assert result["severity"] == "HIGH"

    def test_handles_dict_with_cve_id_underscore(self):
        """Dict with cve_id (underscore) field should normalize to id."""
        d = {"cve_id": "CVE-2024-5678", "severity": "MEDIUM"}
        result = _coerce_to_cve_item(d)
        assert result is not None
        assert result["id"] == "CVE-2024-5678"

    def test_handles_dict_with_cveId_camel(self):
        """Dict with camelCase cveId field should normalize to id."""
        d = {"cveId": "CVE-2024-9999", "severity": "LOW"}
        result = _coerce_to_cve_item(d)
        assert result is not None
        assert result["id"] == "CVE-2024-9999"

    def test_deserializes_json_string(self):
        """JSON string should be parsed and normalized."""
        s = '{"id": "CVE-2024-0001", "severity": "CRITICAL", "cvss": 10.0}'
        result = _coerce_to_cve_item(s)
        assert result is not None
        assert result["id"] == "CVE-2024-0001"
        assert result["severity"] == "CRITICAL"
        assert result["cvss"] == 10.0

    def test_handles_plain_cve_string(self):
        """Plain CVE ID string (not JSON) should return a valid CVE dict."""
        result = _coerce_to_cve_item("CVE-2024-1234")
        assert result is not None
        assert result["id"] == "CVE-2024-1234"
        assert result["severity"] == "LOW"  # Default severity

    def test_handles_lowercase_cve_string(self):
        """Lowercase CVE ID should be normalized to uppercase."""
        result = _coerce_to_cve_item("cve-2024-1234")
        assert result is not None
        assert result["id"] == "CVE-2024-1234"

    def test_handles_non_json_string(self):
        """Non-CVE strings should return None gracefully."""
        assert _coerce_to_cve_item("not json at all") is None
        assert _coerce_to_cve_item("some error message") is None

    def test_handles_none(self):
        """None should return None."""
        assert _coerce_to_cve_item(None) is None

    def test_handles_list(self):
        """List should return None (not a valid CVE item)."""
        assert _coerce_to_cve_item(["CVE-1", "CVE-2"]) is None

    def test_handles_int(self):
        """Integer should return None."""
        assert _coerce_to_cve_item(12345) is None

    def test_handles_empty_dict(self):
        """Dict without id field should return None."""
        assert _coerce_to_cve_item({"severity": "HIGH"}) is None
        assert _coerce_to_cve_item({}) is None

    def test_handles_dict_with_defaults(self):
        """Dict missing some fields should use defaults."""
        d = {"id": "CVE-2024-0001"}
        result = _coerce_to_cve_item(d)
        assert result is not None
        assert result["id"] == "CVE-2024-0001"
        assert result["severity"] == "LOW"
        assert result["description"] == ""
        assert result["cvss"] == 0.0


class TestGetCvesForService:
    """Test get_cves_for_service function."""

    def setup_method(self):
        """Reset cache before each test."""
        from cybersec_cli.utils import cve_enrichment
        cve_enrichment._cve_cache = {}

    def test_returns_empty_for_unknown_service(self):
        """Unknown service should return empty list."""
        result = get_cves_for_service("unknown-service-xyz")
        assert result == []

    def test_returns_cached_data(self):
        """Cached service should return CVE list."""
        add_cve_entry("test-service", [
            {"id": "CVE-2024-0001", "severity": "HIGH"}
        ])
        result = get_cves_for_service("test-service")
        assert len(result) == 1
        assert result[0]["id"] == "CVE-2024-0001"

    def test_cache_hit_with_version(self):
        """Version-specific cache entry should be found when version matches."""
        add_cve_entry("nginx", [
            {"id": "CVE-2024-0001", "severity": "HIGH"}
        ], version="1.18.0")
        # Should be found when querying with version
        result = get_cves_for_service("nginx", "1.18.0")
        assert len(result) == 1
        # Should NOT be found when querying without version
        result2 = get_cves_for_service("nginx")
        assert len(result2) == 0


class TestEnrichServiceWithLiveData:
    """Test enrich_service_with_live_data function."""

    def setup_method(self):
        """Reset cache before each test."""
        from cybersec_cli.utils import cve_enrichment
        cve_enrichment._cve_cache = {}

    @pytest.mark.asyncio
    async def test_rejects_no_evidence(self):
        """Should reject when no service info available."""
        result = await enrich_service_with_live_data(
            service="unknown",
            confidence=0.0
        )
        assert result["cve_status"] in ["SKIPPED_UNKNOWN_SERVICE", "SKIPPED_LOW_CONFIDENCE", "SKIPPED_NO_EVIDENCE"]
        assert result["vulnerabilities"] == []

    @pytest.mark.asyncio
    async def test_accepts_service_with_confidence(self):
        """Should proceed with CVE lookup when confidence is high enough."""
        # Add some cached CVEs
        add_cve_entry("ssh", [
            {"id": "CVE-2024-0001", "severity": "HIGH", "cvss": 7.5}
        ])
        
        result = await enrich_service_with_live_data(
            service="ssh",
            confidence=0.9
        )
        assert result["cve_status"] == "SUCCESS_CACHED"
        assert "CVE-2024-0001" in result["vulnerabilities"]

    @pytest.mark.asyncio
    async def test_accepts_service_with_version(self):
        """Should proceed with CVE lookup when version is provided."""
        # Add CVEs for 'http' service (the service name being queried)
        add_cve_entry("http", [
            {"id": "CVE-2024-1234", "severity": "MEDIUM", "cvss": 5.0}
        ])
        
        result = await enrich_service_with_live_data(
            service="http",
            version="2.4.49"
        )
        assert result["cve_status"] == "SUCCESS_CACHED"
        assert "CVE-2024-1234" in result["vulnerabilities"]

    @pytest.mark.asyncio
    async def test_handles_corrupted_cache_entry(self):
        """Regression: cache containing string instead of dict should not crash."""
        from cybersec_cli.utils import cve_enrichment
        
        # Simulate corrupted cache: service maps to a string instead of list of dicts
        cve_enrichment._cve_cache["corrupted-service"] = "CVE-2024-FAKE"
        
        result = await enrich_service_with_live_data(
            service="corrupted-service",
            confidence=0.9
        )
        # Should NOT raise AttributeError, should handle gracefully
        assert result["cve_status"] in ["SUCCESS_CACHED", "NO_CVES_FOUND"]
        assert isinstance(result["vulnerabilities"], list)

    @pytest.mark.asyncio
    async def test_handles_list_of_strings_in_cache(self):
        """Regression: cache containing list of CVE ID strings should not crash."""
        from cybersec_cli.utils import cve_enrichment
        
        # Simulate cache where entries are strings instead of dicts
        cve_enrichment._cve_cache["string-list-service"] = [
            "CVE-2024-STRING-1",
            "CVE-2024-STRING-2"
        ]
        
        result = await enrich_service_with_live_data(
            service="string-list-service",
            confidence=0.9
        )
        # Should NOT raise AttributeError, should handle gracefully
        assert result["cve_status"] == "SUCCESS_CACHED"
        assert "CVE-2024-STRING-1" in result["vulnerabilities"]
        assert "CVE-2024-STRING-2" in result["vulnerabilities"]
