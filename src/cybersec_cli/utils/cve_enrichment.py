"""CVE enrichment for detected services using a local cache or optional API.

Enriches scan results with CVE information for detected services.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False
    # Log warning once at module load time
    import sys
    logging.warning(
        "httpx is not installed. Live CVE enrichment from NVD API will be disabled. "
        "Install httpx to enable live CVE lookups: pip install httpx"
    )

# CVE matching confidence thresholds
# Below MIN_CONFIDENCE_FOR_CVE → return empty, add cve_note
# Above → proceed with NVD lookup
CVE_CONFIDENCE_THRESHOLDS = {
    "require_banner": False,
    "require_service": True,
    "min_confidence": 0.3,
    "version_overrides_confidence": True,
}

MIN_CONFIDENCE_FOR_CVE = 0.3

logger = logging.getLogger(__name__)

# Base paths
BASE_DIR = Path(__file__).parent.parent.parent # src/cybersec_cli/utils -> src/cybersec_cli -> src -> root
REPORTS_DIR = BASE_DIR.parent / "reports"
# Move CVE cache to a more secure location not directly accessible via web
CVE_CACHE_FILE = BASE_DIR.parent / ".secrets" / "cve_cache.json"

# Simple in-memory CVE cache (loaded at startup)
_cve_cache: Dict[str, List[Dict]] = {}
MAX_CACHE_SIZE = 1000


def init_cve_cache():
    """Initialize the CVE cache from file."""
    global _cve_cache
    # Create the secure directory for CVE cache
    CVE_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)

    if CVE_CACHE_FILE.exists():
        try:
            with open(CVE_CACHE_FILE, "r") as f:
                _cve_cache = json.load(f)
            logger.info(f"Loaded CVE cache with {len(_cve_cache)} service entries")
        except Exception as e:
            logger.warning(f"Failed to load CVE cache: {e}")
            _cve_cache = {}
    else:
        _cve_cache = {}
        logger.debug("CVE cache file not found; starting with empty cache")


def _evict_old_entries():
    """Evict oldest entries if cache exceeds MAX_CACHE_SIZE."""
    global _cve_cache
    if len(_cve_cache) > MAX_CACHE_SIZE:
        # Remove oldest entries (first ~10% of keys)
        keys_to_remove = list(_cve_cache.keys())[:max(1, MAX_CACHE_SIZE // 10)]
        for key in keys_to_remove:
            del _cve_cache[key]
        logger.debug(f"Evicted {len(keys_to_remove)} old entries from CVE cache")


def save_cve_cache():
    """Save the CVE cache to file."""
    try:
        # Ensure the directory exists
        CVE_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CVE_CACHE_FILE, "w") as f:
            json.dump(_cve_cache, f, indent=2)
        logger.debug(f"Saved CVE cache with {len(_cve_cache)} service entries")
    except Exception as e:
        logger.exception(f"Failed to save CVE cache: {e}")


def get_cves_for_service(
    service_name: str, version: Optional[str] = None
) -> List[Dict]:
    """Get CVEs for a detected service (e.g., 'ssh', 'http', 'ftp').

    Returns a list of CVE dicts with 'id', 'severity', 'description' fields.
    """
    key = f"{service_name.lower()}"
    if version:
        key += f":{version}"

    if key in _cve_cache:
        return _cve_cache[key]

    # Check if service exists without version
    if f"{service_name.lower()}" in _cve_cache:
        return _cve_cache[f"{service_name.lower()}"]

    return []


def add_cve_entry(
    service_name: str, cves: List[Dict], version: Optional[str] = None
) -> bool:
    """Add or update CVE entries for a service.

    cves should be a list of dicts with 'id', 'severity', 'description'.
    """
    try:
        key = f"{service_name.lower()}"
        if version:
            key += f":{version}"
        _cve_cache[key] = cves
        _evict_old_entries()
        save_cve_cache()
        logger.debug(f"Added {len(cves)} CVEs for service: {key}")
        return True
    except Exception as e:
        logger.exception(f"Failed to add CVE entry: {e}")
        return False


class CVESearchAPI:
    """Class to handle interactions with external CVE APIs (NVD 2.0)."""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    @staticmethod
    async def fetch_cves(service: str, version: Optional[str] = None) -> List[Dict]:
        """Fetch CVEs from NVD 2.0 API."""
        if not HAS_HTTPX:
            # Only log once per session to avoid spam
            if not hasattr(CVESearchAPI, "_httpx_warning_logged"):
                logger.warning("httpx not installed; cannot fetch live CVEs. Install with: pip install httpx")
                CVESearchAPI._httpx_warning_logged = True
            return []

        # Try specific search first, then fallback to just service
        results = await CVESearchAPI._do_fetch(service, version)
        if not results and version:
            logger.debug(f"No results for {service} {version}, trying just {service}")
            results = await CVESearchAPI._do_fetch(service)
        
        return results

    @staticmethod
    async def _do_fetch(service: str, version: Optional[str] = None) -> List[Dict]:
        search_term = service.strip()
        if version and version != "-":
             search_term = f"{service} {version}"
        
        import urllib.parse
        encoded_search = urllib.parse.quote(search_term)
        url = f"{CVESearchAPI.BASE_URL}?keywordSearch={encoded_search}&resultsPerPage=10"
        
        headers = {
            "User-Agent": "Mozilla/5.0 (CyberSec-CLI/0.1.0)",
            "Accept": "application/json"
        }

        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                response = await client.get(url, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    results = []
                    
                    vulnerabilities = data.get("vulnerabilities", [])
                    if not vulnerabilities:
                        return []
                    
                    for item in vulnerabilities:
                        cve_data = item.get("cve", {})
                        cve_id = cve_data.get("id")
                        if not cve_id:
                            continue
                        
                        # Extract CVSS
                        cvss = 0.0
                        metrics = cve_data.get("metrics", {})
                        # Try V3.1, then V3.0, then V2
                        cvss_list = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or metrics.get("cvssMetricV2")
                        if cvss_list:
                            cvss = cvss_list[0].get("cvssData", {}).get("baseScore", 0.0)
                        
                        # Extract description
                        descriptions = cve_data.get("descriptions", [])
                        summary = "No description available"
                        for desc in descriptions:
                            if desc.get("lang") == "en":
                                summary = desc.get("value", summary)
                                break
                        
                        severity = "LOW"
                        if cvss >= 9.0:
                            severity = "CRITICAL"
                        elif cvss >= 7.0:
                            severity = "HIGH"
                        elif cvss >= 4.0:
                            severity = "MEDIUM"

                        results.append({
                            "id": cve_id,
                            "severity": severity,
                            "description": summary,
                            "cvss": float(cvss)
                        })
                    
                    # Sort by CVSS descending
                    results.sort(key=lambda x: x.get("cvss", 0), reverse=True)
                    return results[:5] 
                
                elif response.status_code == 403:
                    logger.warning(f"NVD API returned 403 (Rate Limited?) for {url}")
                    return []
                else:
                    logger.warning(f"NVD API returned {response.status_code} for {url}")
                    return []
        except Exception as e:
            logger.error(f"Error fetching CVEs for {search_term}: {str(e)}")
            return []


async def enrich_service_with_live_data(
    service: str,
    version: Optional[str] = None,
    banner: Optional[str] = None,
    confidence: float = 0.0,
) -> Dict:
    """Attempt to fetch live data if not in cache.
    
    Returns empty result if confidence is too low to make
    meaningful CVE assignments — avoids misleading output.
    
    Args:
        service: Service name (e.g., 'ssh', 'http')
        version: Optional version string
        banner: Optional banner response from service
        confidence: Confidence level (0.0-1.0) for service detection
        
    Returns:
        Dict with 'vulnerabilities', 'cvss_score', 'cve_note', 'cve_status' keys
    """
    # Gate 1: Reject if no evidence of what's actually running
    # (confidence=0 AND no banner AND no version)
    has_version = version and version not in {"unknown", ""}
    if confidence == 0 and not banner and not has_version:
        return {
            "vulnerabilities": [],
            "cvss_score": 0,
            "cve_note": "Service unidentified (confidence=0, no banner, no version). "
                        "CVE matching skipped to avoid false positives. "
                        "Identify service manually before assessing CVEs.",
            "cve_status": "SKIPPED_LOW_CONFIDENCE"
        }
    
    # Gate 2: Reject generic/unknown service labels with no version
    if service in {"unknown", "", None} and not version:
        return {
            "vulnerabilities": [],
            "cvss_score": 0,
            "cve_note": f"Service type unknown on this port. "
                        f"CVE matching requires confirmed service identity.",
            "cve_status": "SKIPPED_UNKNOWN_SERVICE"
        }
    
    # Gate 3: Only assign CVEs when we have something real to match on
    # (service name confirmed OR version string present OR banner captured)
    has_evidence = (
        (service and service not in {"unknown", ""}) or
        (version and version not in {"unknown", ""}) or
        (banner and len(banner) > 10)
    )
    
    if not has_evidence:
        return {
            "vulnerabilities": [],
            "cvss_score": 0,
            "cve_note": "Insufficient evidence for CVE matching.",
            "cve_status": "SKIPPED_NO_EVIDENCE"
        }
    
    # Check confidence threshold (unless we have version or banner which overrides confidence)
    has_version = version and version not in {"unknown", ""}
    has_banner = banner and len(banner) > 10
    if confidence < MIN_CONFIDENCE_FOR_CVE and not has_version and not has_banner:
        return {
            "vulnerabilities": [],
            "cvss_score": 0,
            "cve_note": f"Low confidence ({confidence:.1f}). CVE matching requires "
                        f"higher confidence or version information.",
            "cve_status": "SKIPPED_LOW_CONFIDENCE"
        }
    
    # Proceed with real CVE lookup
    cached = get_cves_for_service(service, version)
    if cached:
        cve_ids = [cve.get("id") for cve in cached if cve.get("id")]
        return {
            "vulnerabilities": cve_ids,
            "cvss_score": max((cve.get("cvss", 0) for cve in cached), default=0),
            "cve_note": f"CVE data from cache for {service}",
            "cve_status": "SUCCESS_CACHED"
        }
    
    # Not in cache, try fetch
    logger.info(f"Fetching live CVE data for {service} {version}")
    live_cves = await CVESearchAPI.fetch_cves(service, version)
    
    if live_cves:
        add_cve_entry(service, live_cves, version)
        cve_ids = [cve.get("id") for cve in live_cves if cve.get("id")]
        return {
            "vulnerabilities": cve_ids,
            "cvss_score": max((cve.get("cvss", 0) for cve in live_cves), default=0),
            "cve_note": f"CVE data fetched from NVD for {service}",
            "cve_status": "SUCCESS_LIVE"
        }
        
    return {
        "vulnerabilities": [],
        "cvss_score": 0,
        "cve_note": f"No CVEs found for {service}",
        "cve_status": "NO_CVES_FOUND"
    }


async def enrich_scan_result(scan_output: str) -> Dict:
    """Enrich a scan result with CVE information (Async).

    Parses open ports from the scan output and enriches with CVEs for detected services.
    Returns a dict with 'services' and 'cves' keys.
    """
    try:
        services = {}
        cves_found = {}

        # Simple parsing: look for port detection patterns
        # Example: "22/tcp open ssh" or similar patterns
        for line in scan_output.splitlines():
            line = line.strip()
            if not line:
                continue
                
            parts = line.split()
            # Check for valid port line: "22/tcp open ..."
            if len(parts) >= 3 and parts[1].lower() == "open" and ("/" in parts[0]):
                port_proto = parts[0]
                
                # Double check it looks like a port line
                if not (parts[0].endswith("/tcp") or parts[0].endswith("/udp")):
                    continue

                # Attempt to parse service and version
                # Format often: 22/tcp open ssh OpenSSH 7.9
                service = parts[2] if len(parts) > 2 else "unknown"
                version = None
                if len(parts) > 3:
                    # Very naive version extraction
                     version = " ".join(parts[3:])

                services[port_proto] = f"{service} {version}" if version else service

                # Look up CVEs for this service
                service_cves = await enrich_service_with_live_data(service, version)
                if service_cves:
                    cves_found[service] = service_cves

        return {
            "services": services,
            "cves": cves_found,
            "total_cves": sum(len(v) for v in cves_found.values()),
        }
    except Exception as e:
        logger.exception(f"Error enriching scan result: {e}")
        return {"services": {}, "cves": {}, "total_cves": 0}


def populate_sample_cves():
    """Populate the cache with sample CVE data for common services.

    This is a demo function; in production, you'd load from NVD or an API.
    """
    sample_data = {
        "ssh": [
            {
                "id": "CVE-2023-12345",
                "severity": "HIGH",
                "description": "OpenSSH authentication bypass",
            },
            {
                "id": "CVE-2023-54321",
                "severity": "MEDIUM",
                "description": "OpenSSH information disclosure",
            },
        ],
        "http": [
            {
                "id": "CVE-2023-88888",
                "severity": "CRITICAL",
                "description": "HTTP server DoS vulnerability",
            },
        ],
        "ftp": [
            {
                "id": "CVE-2023-99999",
                "severity": "HIGH",
                "description": "FTP unauthorized access",
            },
        ],
    }

    for service, cves in sample_data.items():
        add_cve_entry(service, cves)

    logger.info("Populated sample CVE data")
