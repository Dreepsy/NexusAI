import time
from typing import List, Dict
from ..core.config import get_config, get_logger
from ..core.http_client import get_http_client

# Get configuration and logger
config = get_config()
logger = get_logger()
http_client = get_http_client()

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Developer Note:
# This function fetches CVEs from the NVD for a given service and version.
# For high-volume or production use, you should request an NVD API key and handle rate limits.
# For most CLI use, this public endpoint is sufficient.
def fetch_cves(service, version, max_results=5):
    """
    Fetch CVEs from the NVD for a given service and version string.
    Returns a list of dicts: [{"id": ..., "description": ...}, ...]
    
    Args:
        service (str): The service name to search for
        version (str): The service version
        max_results (int): Maximum number of CVEs to return
        
    Returns:
        list: List of CVE dictionaries with 'id' and 'description' keys
    """
    query = f"{service} {version}"
    params = {
        "keywordSearch": query,
        "resultsPerPage": max_results
    }
    
    try:
        response = http_client.get(NVD_API_URL, params=params)
        
        if response.get('error'):
            logger.error("NVD API request failed", 
                        service=service, 
                        version=version, 
                        error=response.get('message', 'Unknown error'))
            return []
        
        data = response.get('data', {})
        cves = []
        
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descs = cve.get("descriptions", [])
            desc = descs[0]["value"] if descs else "No description."
            cves.append({"id": cve_id, "description": desc})
        
        logger.info("Successfully fetched CVEs", 
                   service=service, 
                   version=version, 
                   count=len(cves))
        return cves
        
    except Exception as e:
        logger.error("Unexpected error fetching CVEs", 
                    service=service, 
                    version=version, 
                    error=str(e))
        return []

# Example usage for developers
def _demo():
    service = "apache"
    version = "2.4.49"
    cves = fetch_cves(service, version)
    print(f"Found {len(cves)} CVEs for {service} {version}:")
    for cve in cves:
        print(f"- {cve['id']}: {cve['description'][:100]}...")

if __name__ == "__main__":
    _demo()