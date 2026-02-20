"""Test for CVE confidence gating fix."""

import asyncio
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.cybersec_cli.utils.cve_enrichment import enrich_service_with_live_data


async def test_cve_confidence_gate():
    """Test the CVE confidence gating logic."""
    
    print("Testing CVE confidence gating...")
    print("=" * 60)
    
    # Case 1: confidence=0, no banner → should return empty with SKIPPED status
    print("\nCase 1: confidence=0, no banner → should return empty")
    result = await enrich_service_with_live_data(
        service="unknown",
        version=None,
        banner=None,
        confidence=0
    )
    print(f"Result: {result}")
    assert result["vulnerabilities"] == [], f"FAIL: expected empty list, got {result['vulnerabilities']}"
    assert result["cve_status"] == "SKIPPED_LOW_CONFIDENCE"
    print("✅ Case 1 (no confidence, no banner): empty CVEs returned")
    
    # Case 2: confidence=0, banner present → should attempt lookup
    print("\nCase 2: confidence=0, banner present → should attempt lookup")
    result = await enrich_service_with_live_data(
        service="ssh",
        version=None,
        banner="SSH-2.0-OpenSSH_8.0",
        confidence=0
    )
    print(f"Result: {result}")
    assert result["cve_status"] != "SKIPPED_LOW_CONFIDENCE", f"FAIL: should attempt lookup with banner, got {result['cve_status']}"
    print("✅ Case 2 (banner present despite confidence=0): lookup attempted")
    
    # Case 3: version known → always attempt lookup
    print("\nCase 3: version known → always attempt lookup")
    result = await enrich_service_with_live_data(
        service="exim",
        version="4.99.1",
        banner=None,
        confidence=0
    )
    print(f"Result: {result}")
    assert result["cve_status"] != "SKIPPED_LOW_CONFIDENCE", f"FAIL: version should override confidence, got {result['cve_status']}"
    print("✅ Case 3 (version known): lookup attempted regardless of confidence")
    
    # Case 4: The exact scan scenario that was broken
    # Generic port with no evidence — must return empty
    print("\nCase 4: exact broken scenario - unknown service, no evidence")
    result = await enrich_service_with_live_data(
        service="unknown",
        version="unknown",
        banner="",
        confidence=0
    )
    print(f"Result: {result}")
    assert result["vulnerabilities"] == []
    assert len(result["vulnerabilities"]) == 0
    print("✅ Case 4 (exact broken scenario): no false CVEs returned")
    
    # Case 5: High confidence with service → should work
    print("\nCase 5: High confidence with known service → should work")
    result = await enrich_service_with_live_data(
        service="ssh",
        version=None,
        banner=None,
        confidence=0.9
    )
    print(f"Result: {result}")
    # This might return from cache or live, but shouldn't be skipped
    assert result["cve_status"] in ["SUCCESS_CACHED", "SUCCESS_LIVE", "NO_CVES_FOUND"], f"FAIL: unexpected status {result['cve_status']}"
    print("✅ Case 5 (high confidence): CVE lookup attempted")
    
    # Case 6: Unknown service without version or banner → should skip
    print("\nCase 6: Unknown service without version or banner")
    result = await enrich_service_with_live_data(
        service="unknown",
        version=None,
        banner=None,
        confidence=0.5
    )
    print(f"Result: {result}")
    assert result["cve_status"] == "SKIPPED_UNKNOWN_SERVICE"
    print("✅ Case 6 (unknown service): skipped with appropriate status")
    
    # Case 7: Empty service name → should skip
    print("\nCase 7: Empty service name")
    result = await enrich_service_with_live_data(
        service="",
        version=None,
        banner=None,
        confidence=0.5
    )
    print(f"Result: {result}")
    assert result["cve_status"] == "SKIPPED_UNKNOWN_SERVICE"
    print("✅ Case 7 (empty service): skipped with appropriate status")
    
    print("\n" + "=" * 60)
    print("ALL CASES PASS — CVE confidence gate working correctly")


if __name__ == "__main__":
    asyncio.run(test_cve_confidence_gate())
