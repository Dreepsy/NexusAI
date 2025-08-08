import pandas as pd
import os
import re
from typing import List, Dict, Optional
from ..core.config import get_config, get_logger
from ..core.http_client import get_http_client

# Get configuration and logger
config = get_config()
logger = get_logger()
http_client = get_http_client()

# Paths to Exploit-DB files
EXPLOIT_DB_PATH = os.path.join(os.path.dirname(__file__), '../Exploit-DB/files_exploits.csv')
SHELLCODE_DB_PATH = os.path.join(os.path.dirname(__file__), '../Exploit-DB/files_shellcodes.csv')

# CISA KEV API endpoint
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Vendor advisory mappings - Simplified to essential vendors only
VENDOR_ADVISORY_LINKS = {
    # Web servers
    'apache': 'https://httpd.apache.org/security/vulnerabilities_24.html',
    'nginx': 'https://nginx.org/en/security_advisories.html',
    
    # SSH and remote access
    'openssh': 'https://www.openssh.com/security.html',
    'ssh': 'https://www.openssh.com/security.html',
    
    # Databases
    'mysql': 'https://www.mysql.com/support/security/',
    'postgresql': 'https://www.postgresql.org/support/security/',
    'redis': 'https://redis.io/topics/security',
    'mongodb': 'https://www.mongodb.com/alerts',
    'elasticsearch': 'https://www.elastic.co/support/security',
    
    # Containerization and orchestration
    'docker': 'https://docs.docker.com/engine/security/',
    'kubernetes': 'https://kubernetes.io/docs/reference/issues-security/',
    
    # CI/CD and development
    'jenkins': 'https://www.jenkins.io/security/',
    'gitlab': 'https://about.gitlab.com/security/',
    'github': 'https://github.blog/category/security/',
    
    # Content management systems
    'wordpress': 'https://wordpress.org/news/category/security/',
    'drupal': 'https://www.drupal.org/security',
    'joomla': 'https://developer.joomla.org/security-centre.html',
    
    # E-commerce platforms
    'magento': 'https://magento.com/security/patches',
    'shopify': 'https://shopify.dev/security',
    
    # Enterprise software
    'salesforce': 'https://help.salesforce.com/s/articleView?id=sf.security_patches.htm',
    'oracle': 'https://www.oracle.com/security-alerts/',
    'microsoft': 'https://msrc.microsoft.com/update-guide',
    
    # Network equipment
    'cisco': 'https://tools.cisco.com/security/center/publicationListing.x',
    'juniper': 'https://supportportal.juniper.net/s/article/2023-01-Security-Bulletin-Junos-OS-SRX-Series-and-NFX-Series-Self-signed-Certificate-Vulnerability-CVE-2023-22490?language=en_US',
    'fortinet': 'https://fortiguard.com/psirt',
    'paloalto': 'https://security.paloaltonetworks.com/',
    'checkpoint': 'https://supportcontent.checkpoint.com/solutions?id=sk180412',
    'f5': 'https://support.f5.com/csp/article/K18032112',
    
    # Virtualization and remote access
    'citrix': 'https://support.citrix.com/article/CTX267027',
    'vmware': 'https://www.vmware.com/security/advisories.html',
    'rdp': 'https://msrc.microsoft.com/update-guide',
    
    # Adobe products (essential only)
    'adobe': 'https://helpx.adobe.com/security.html',
    'adobe_reader': 'https://helpx.adobe.com/reader/kb/archived-versions.html',
    'adobe_acrobat': 'https://helpx.adobe.com/acrobat/kb/archived-versions.html',
    'adobe_flash': 'https://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html',
}

def load_exploit_db():
    """
    Load Exploit-DB data from CSV files.
    Returns a pandas DataFrame with exploit information.
    """
    try:
        if os.path.exists(EXPLOIT_DB_PATH):
            df = pd.read_csv(EXPLOIT_DB_PATH)
            logger.info("Successfully loaded Exploit-DB", count=len(df))
            return df
        else:
            logger.warning("Exploit-DB file not found", path=EXPLOIT_DB_PATH)
            return pd.DataFrame()
    except Exception as e:
        logger.error("Failed to load Exploit-DB", error=str(e))
        return pd.DataFrame()

def search_exploits(cve_list: List[str], service: str = None, max_results: int = 5) -> List[Dict]:
    """
    Search Exploit-DB for exploits related to given CVEs or service.
    Returns a list of exploit information.
    """
    df = load_exploit_db()
    if df.empty:
        return []
    
    exploits = []
    
    # Search by CVE
    for cve in cve_list:
        cve_matches = df[df['codes'].str.contains(cve, case=False, na=False)]
        for _, row in cve_matches.head(max_results).iterrows():
            exploits.append({
                'id': row.get('id', ''),
                'file': row.get('file', ''),
                'description': row.get('description', ''),
                'date': row.get('date', ''),
                'author': row.get('author', ''),
                'type': row.get('type', ''),
                'platform': row.get('platform', ''),
                'port': row.get('port', ''),
                'cve': cve
            })
    
    # Search by service name if provided
    if service and service.lower() in VENDOR_ADVISORY_LINKS:
        service_matches = df[df['description'].str.contains(service, case=False, na=False)]
        for _, row in service_matches.head(max_results).iterrows():
            exploits.append({
                'id': row.get('id', ''),
                'file': row.get('file', ''),
                'description': row.get('description', ''),
                'date': row.get('date', ''),
                'author': row.get('author', ''),
                'type': row.get('type', ''),
                'platform': row.get('platform', ''),
                'port': row.get('port', ''),
                'service': service
            })
    
    return exploits[:max_results]

def check_cisa_kev(cve_list: List[str]) -> Dict[str, bool]:
    """
    Check which CVEs are in the CISA Known Exploited Vulnerabilities catalog.
    Returns a dict mapping CVE to boolean (True if in KEV).
    """
    try:
        response = http_client.get(CISA_KEV_URL)
        
        if response.get('error'):
            logger.warning("Failed to fetch CISA KEV", error=response.get('message', 'Unknown error'))
            return {cve: False for cve in cve_list}
        
        data = response.get('data', {})
        kev_cves = {vuln['cveID'] for vuln in data.get('vulnerabilities', [])}
        
        result = {cve: cve in kev_cves for cve in cve_list}
        logger.info("Successfully checked CISA KEV", 
                   total_cves=len(cve_list), 
                   kev_count=sum(result.values()))
        return result
        
    except Exception as e:
        logger.error("CISA KEV check failed", error=str(e))
        return {cve: False for cve in cve_list}

def get_vendor_advisory_link(service: str) -> Optional[str]:
    """
    Get vendor advisory link for a given service.
    Returns the advisory URL if available.
    """
    service_lower = service.lower()
    return VENDOR_ADVISORY_LINKS.get(service_lower)

def enrich_cves_with_threat_intel(cve_list: List[Dict], service: str = None) -> Dict:
    """
    Enrich CVE list with threat intelligence from multiple sources.
    Returns enriched information including exploits, KEV status, and vendor links.
    """
    cve_ids = [cve['id'] for cve in cve_list]
    
    # Get exploits from Exploit-DB
    exploits = search_exploits(cve_ids, service)
    
    # Check CISA KEV status
    kev_status = check_cisa_kev(cve_ids)
    
    # Get vendor advisory link
    vendor_link = get_vendor_advisory_link(service) if service else None
    
    result = {
        'exploits': exploits,
        'kev_status': kev_status,
        'vendor_advisory': vendor_link,
        'summary': {
            'total_cves': len(cve_list),
            'exploits_found': len(exploits),
            'kev_count': sum(kev_status.values()),
            'has_vendor_link': vendor_link is not None
        }
    }
    
    logger.info("Successfully enriched CVEs with threat intelligence",
                service=service,
                total_cves=len(cve_list),
                exploits_found=len(exploits),
                kev_count=sum(kev_status.values()))
    
    return result

# Example usage for developers
if __name__ == "__main__":
    # Test with sample CVEs
    test_cves = [
        {"id": "CVE-2021-41773", "description": "Apache HTTP Server path traversal"},
        {"id": "CVE-2021-42013", "description": "Apache HTTP Server RCE"}
    ]
    
    result = enrich_cves_with_threat_intel(test_cves, "apache")
    print("Threat Intelligence Results:")
    print(f"Exploits found: {len(result['exploits'])}")
    print(f"KEV CVEs: {sum(result['kev_status'].values())}")
    print(f"Vendor advisory: {result['vendor_advisory']}") 