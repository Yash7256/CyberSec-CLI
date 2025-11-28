"""CVE enrichment for detected services using a local cache or optional API.

Enriches scan results with CVE information for detected services.
"""
import json
import logging
from pathlib import Path
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

# Base paths
BASE_DIR = Path(__file__).parent
REPORTS_DIR = Path(BASE_DIR).parent / 'reports'
CVE_CACHE_FILE = REPORTS_DIR / 'cve_cache.json'

# Simple in-memory CVE cache (loaded at startup)
_cve_cache: Dict[str, List[Dict]] = {}


def init_cve_cache():
    """Initialize the CVE cache from file."""
    global _cve_cache
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    
    if CVE_CACHE_FILE.exists():
        try:
            with open(CVE_CACHE_FILE, 'r') as f:
                _cve_cache = json.load(f)
            logger.info(f'Loaded CVE cache with {len(_cve_cache)} service entries')
        except Exception as e:
            logger.warning(f'Failed to load CVE cache: {e}')
            _cve_cache = {}
    else:
        _cve_cache = {}
        logger.debug('CVE cache file not found; starting with empty cache')


def save_cve_cache():
    """Save the CVE cache to file."""
    try:
        with open(CVE_CACHE_FILE, 'w') as f:
            json.dump(_cve_cache, f, indent=2)
        logger.debug(f'Saved CVE cache with {len(_cve_cache)} service entries')
    except Exception as e:
        logger.exception(f'Failed to save CVE cache: {e}')


def get_cves_for_service(service_name: str, version: Optional[str] = None) -> List[Dict]:
    """Get CVEs for a detected service (e.g., 'ssh', 'http', 'ftp').
    
    Returns a list of CVE dicts with 'id', 'severity', 'description' fields.
    """
    key = f'{service_name.lower()}'
    if version:
        key += f':{version}'
    
    if key in _cve_cache:
        return _cve_cache[key]
    
    # Check if service exists without version
    if f'{service_name.lower()}' in _cve_cache:
        return _cve_cache[f'{service_name.lower()}']
    
    return []


def add_cve_entry(service_name: str, cves: List[Dict], version: Optional[str] = None) -> bool:
    """Add or update CVE entries for a service.
    
    cves should be a list of dicts with 'id', 'severity', 'description'.
    """
    try:
        key = f'{service_name.lower()}'
        if version:
            key += f':{version}'
        _cve_cache[key] = cves
        save_cve_cache()
        logger.debug(f'Added {len(cves)} CVEs for service: {key}')
        return True
    except Exception as e:
        logger.exception(f'Failed to add CVE entry: {e}')
        return False


def enrich_scan_result(scan_output: str) -> Dict:
    """Enrich a scan result with CVE information.
    
    Parses open ports from the scan output and enriches with CVEs for detected services.
    Returns a dict with 'services' and 'cves' keys.
    """
    try:
        services = {}
        cves_found = {}
        
        # Simple parsing: look for port detection patterns
        # Example: "22/tcp open ssh" or similar patterns
        for line in scan_output.splitlines():
            if '/tcp open' in line.lower() or '/udp open' in line.lower():
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0]
                    service = parts[2] if len(parts) > 2 else 'unknown'
                    
                    services[port_proto] = service
                    
                    # Look up CVEs for this service
                    service_cves = get_cves_for_service(service)
                    if service_cves:
                        cves_found[service] = service_cves
        
        return {
            'services': services,
            'cves': cves_found,
            'total_cves': sum(len(v) for v in cves_found.values())
        }
    except Exception as e:
        logger.exception(f'Error enriching scan result: {e}')
        return {'services': {}, 'cves': {}, 'total_cves': 0}


def populate_sample_cves():
    """Populate the cache with sample CVE data for common services.
    
    This is a demo function; in production, you'd load from NVD or an API.
    """
    sample_data = {
        'ssh': [
            {'id': 'CVE-2023-12345', 'severity': 'HIGH', 'description': 'OpenSSH authentication bypass'},
            {'id': 'CVE-2023-54321', 'severity': 'MEDIUM', 'description': 'OpenSSH information disclosure'},
        ],
        'http': [
            {'id': 'CVE-2023-88888', 'severity': 'CRITICAL', 'description': 'HTTP server DoS vulnerability'},
        ],
        'ftp': [
            {'id': 'CVE-2023-99999', 'severity': 'HIGH', 'description': 'FTP unauthorized access'},
        ],
    }
    
    for service, cves in sample_data.items():
        add_cve_entry(service, cves)
    
    logger.info('Populated sample CVE data')
