import pytest
import json
from unittest.mock import patch, AsyncMock, MagicMock
from cybersec_cli.utils.cve_enrichment import enrich_scan_result, CVESearchAPI

@pytest.mark.asyncio
async def test_cve_search_api_fetch():
    """Test fetching CVEs from external API (mocked)."""
    # Mock the response object
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "results": [
            {
                "id": "CVE-2023-TEST",
                "cvss": 9.8,
                "summary": "Test vulnerability"
            }
        ]
    }

    # Mock the client instance
    mock_client_instance = AsyncMock()
    mock_client_instance.get.return_value = mock_response

    # Patch AsyncClient to return our mock instance on __aenter__
    with patch("httpx.AsyncClient") as try_mock_client:
        try_mock_client.return_value.__aenter__.return_value = mock_client_instance
        
        # Test static method
        results = await CVESearchAPI.fetch_cves("apache")
        assert len(results) > 0
        assert results[0]["id"] == "CVE-2023-TEST"
        assert results[0]["severity"] == "CRITICAL"

@pytest.mark.asyncio
async def test_enrich_scan_result_integration():
    """Test full enrichment flow with mocked API."""
    scan_output = """
    PORT     STATE SERVICE VERSION
    22/tcp   open  ssh     OpenSSH 7.9
    80/tcp   open  http    Apache httpd 2.4.49
    """
    
    # We patch the class method directly
    with patch("cybersec_cli.utils.cve_enrichment.CVESearchAPI.fetch_cves", new_callable=AsyncMock) as mock_fetch:
        mock_fetch.return_value = [
            {"id": "CVE-MOCK-1", "severity": "HIGH", "description": "Mock CVE", "cvss": 7.5}
        ]
        
        result = await enrich_scan_result(scan_output)
        
        assert "services" in result
        # Check that we found the service
        assert "22/tcp" in result["services"]
        assert "scan" not in result["services"] # Just ensuring no garbage
        
        services_found = result["services"]
        cves_found = result["cves"]
        
        print(f"DEBUG: Services: {services_found}")
        print(f"DEBUG: CVEs: {cves_found}")

        # The service name extracted is "ssh" and "http"
        assert "ssh" in cves_found
        assert cves_found["ssh"][0]["id"] == "CVE-MOCK-1"
