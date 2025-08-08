import json
import os
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from ..core.config import get_config, get_logger
from ..core.http_client import get_http_client

# Get configuration and logger
config = get_config()
logger = get_logger()
http_client = get_http_client()

# MITRE ATT&CK API endpoints (using correct API)
ATTACK_ENTERPRISE_API = "https://attack.mitre.org/api/enterprise/techniques/"
ATTACK_ENTERPRISE_TACTICS = "https://attack.mitre.org/api/enterprise/tactics/"
ATTACK_GROUPS = "https://attack.mitre.org/api/groups/"

# CVE to ATT&CK technique mappings (common mappings)
CVE_TO_TECHNIQUE_MAPPINGS = {
    # Common web vulnerabilities
    "CVE-2021-41773": ["T1190"],  # Apache path traversal -> Exploit Public-Facing Application
    "CVE-2021-42013": ["T1190"],  # Apache RCE -> Exploit Public-Facing Application
    "CVE-2021-44228": ["T1190", "T1059"],  # Log4Shell -> Exploit Public-Facing Application, Command and Scripting Interpreter
    "CVE-2021-34527": ["T1190"],  # PrintNightmare -> Exploit Public-Facing Application
    "CVE-2021-1675": ["T1190"],   # PrintNightmare -> Exploit Public-Facing Application
    
    # SSH related
    "CVE-2018-15473": ["T1078"],  # SSH user enumeration -> Valid Accounts
    "CVE-2016-6210": ["T1078"],   # SSH timing attack -> Valid Accounts
    
    # Database vulnerabilities
    "CVE-2012-2122": ["T1078"],   # MySQL authentication bypass -> Valid Accounts
    "CVE-2016-6662": ["T1190"],   # MySQL privilege escalation -> Exploit Public-Facing Application
    
    # RDP vulnerabilities
    "CVE-2019-0708": ["T1190"],   # BlueKeep -> Exploit Public-Facing Application
    "CVE-2019-1181": ["T1190"],   # BlueKeep variant -> Exploit Public-Facing Application
    
    # SMB vulnerabilities
    "CVE-2017-0143": ["T1190"],   # EternalBlue -> Exploit Public-Facing Application
    "CVE-2017-0144": ["T1190"],   # EternalBlue -> Exploit Public-Facing Application
    "CVE-2017-0145": ["T1190"],   # EternalBlue -> Exploit Public-Facing Application
    "CVE-2017-0146": ["T1190"],   # EternalBlue -> Exploit Public-Facing Application
    "CVE-2017-0147": ["T1190"],   # EternalBlue -> Exploit Public-Facing Application
    "CVE-2017-0148": ["T1190"],   # EternalBlue -> Exploit Public-Facing Application
}

# Service to ATT&CK technique mappings
SERVICE_TO_TECHNIQUE_MAPPINGS = {
    "ssh": {
        "default_techniques": ["T1078", "T1021.004"],  # Valid Accounts, Remote Services: SSH
        "weak_config": ["T1078.003"],  # Valid Accounts: Local Accounts
        "default_credentials": ["T1078.001"],  # Valid Accounts: Default Accounts
    },
    "ftp": {
        "default_techniques": ["T1071.002", "T1078"],  # Application Layer Protocol: File Transfer Protocols, Valid Accounts
        "anonymous_access": ["T1078.002"],  # Valid Accounts: Domain Accounts
    },
    "telnet": {
        "default_techniques": ["T1071.001", "T1078"],  # Application Layer Protocol: Web Protocols, Valid Accounts
    },
    "http": {
        "default_techniques": ["T1071.001", "T1190"],  # Application Layer Protocol: Web Protocols, Exploit Public-Facing Application
        "admin_panel": ["T1078", "T1071.001"],  # Valid Accounts, Application Layer Protocol: Web Protocols
    },
    "https": {
        "default_techniques": ["T1071.001", "T1190"],  # Application Layer Protocol: Web Protocols, Exploit Public-Facing Application
    },
    "mysql": {
        "default_techniques": ["T1078", "T1071.001"],  # Valid Accounts, Application Layer Protocol: Web Protocols
    },
    "postgresql": {
        "default_techniques": ["T1078", "T1071.001"],  # Valid Accounts, Application Layer Protocol: Web Protocols
    },
    "redis": {
        "default_techniques": ["T1078", "T1071.001"],  # Valid Accounts, Application Layer Protocol: Web Protocols
    },
    "mongodb": {
        "default_techniques": ["T1078", "T1071.001"],  # Valid Accounts, Application Layer Protocol: Web Protocols
    },
    "rdp": {
        "default_techniques": ["T1021.001", "T1078"],  # Remote Services: Remote Desktop Protocol, Valid Accounts
    },
    "smb": {
        "default_techniques": ["T1021.002", "T1078"],  # Remote Services: SMB/Windows Admin Shares, Valid Accounts
    },
}

# Threat actors known for specific techniques
THREAT_ACTORS_BY_TECHNIQUE = {
    "T1190": ["APT28", "APT29", "Lazarus Group", "APT41", "APT40"],  # Exploit Public-Facing Application
    "T1078": ["APT28", "APT29", "APT41", "APT40", "Lazarus Group"],  # Valid Accounts
    "T1059": ["APT28", "APT29", "APT41", "APT40", "Lazarus Group"],  # Command and Scripting Interpreter
    "T1021": ["APT28", "APT29", "APT41", "APT40", "Lazarus Group"],  # Remote Services
    "T1071": ["APT28", "APT29", "APT41", "APT40", "Lazarus Group"],  # Application Layer Protocol
}

class MitreAttackMapper:
    """
    Maps security findings to MITRE ATT&CK framework techniques, tactics, and threat actors.
    """
    
    def __init__(self):
        self.techniques_cache = {}
        self.tactics_cache = {}
        self.groups_cache = {}
        self._load_attack_data()
    
    def _load_attack_data(self):
        """Load ATT&CK data from MITRE's API or cache."""
        try:
            # For now, use fallback data to avoid API errors
            # The MITRE ATT&CK API endpoints have changed and require authentication
            logger.info("Using fallback ATT&CK data to avoid API errors")
            self._load_fallback_data()
            
        except Exception as e:
            logger.error("Failed to load ATT&CK data", error=str(e))
            # Use fallback data if API fails
            self._load_fallback_data()
    
    def _load_fallback_data(self):
        """Load fallback ATT&CK data if API is unavailable."""
        logger.info("Loading fallback ATT&CK data")
        self.techniques_cache = {
            "T1190": {
                "name": "Exploit Public-Facing Application",
                "description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior.",
                "tactic": "TA0001"
            },
            "T1078": {
                "name": "Valid Accounts",
                "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
                "tactic": "TA0001"
            },
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
                "tactic": "TA0002"
            },
            "T1021": {
                "name": "Remote Services",
                "description": "Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections.",
                "tactic": "TA0008"
            },
            "T1071": {
                "name": "Application Layer Protocol",
                "description": "Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic.",
                "tactic": "TA0011"
            }
        }
        
        self.tactics_cache = {
            "TA0001": {"name": "Initial Access", "description": "The adversary is trying to get into your network."},
            "TA0002": {"name": "Execution", "description": "The adversary is trying to run malicious code."},
            "TA0008": {"name": "Lateral Movement", "description": "The adversary is trying to move through your environment."},
            "TA0011": {"name": "Command and Control", "description": "The adversary is trying to communicate with compromised systems to control them."}
        }
    
    def map_cve_to_techniques(self, cve_id: str) -> List[str]:
        """Map a CVE to ATT&CK techniques."""
        return CVE_TO_TECHNIQUE_MAPPINGS.get(cve_id, [])
    
    def map_service_to_techniques(self, service: str, context: str = "default") -> List[str]:
        """Map a service to ATT&CK techniques based on context."""
        service_lower = service.lower()
        if service_lower in SERVICE_TO_TECHNIQUE_MAPPINGS:
            service_mappings = SERVICE_TO_TECHNIQUE_MAPPINGS[service_lower]
            if context in service_mappings:
                return service_mappings[context]
            return service_mappings.get("default_techniques", [])
        return []
    
    def get_technique_details(self, technique_id: str) -> Optional[Dict]:
        """Get detailed information about an ATT&CK technique."""
        if isinstance(self.techniques_cache, list):
            # API response format
            for technique in self.techniques_cache:
                if technique.get("attack_id") == technique_id:
                    return technique
        else:
            # Fallback format
            return self.techniques_cache.get(technique_id)
        return None
    
    def get_tactic_details(self, tactic_id: str) -> Optional[Dict]:
        """Get detailed information about an ATT&CK tactic."""
        if isinstance(self.tactics_cache, list):
            # API response format
            for tactic in self.tactics_cache:
                if tactic.get("attack_id") == tactic_id:
                    return tactic
        else:
            # Fallback format
            return self.tactics_cache.get(tactic_id)
        return None
    
    def get_threat_actors(self, technique_ids: List[str]) -> List[str]:
        """Get threat actors known for using specific techniques."""
        actors = set()
        for technique_id in technique_ids:
            if technique_id in THREAT_ACTORS_BY_TECHNIQUE:
                actors.update(THREAT_ACTORS_BY_TECHNIQUE[technique_id])
        return list(actors)
    
    def calculate_risk_score(self, techniques: List[str]) -> int:
        """Calculate risk score based on ATT&CK techniques (1-10 scale)."""
        if not techniques:
            return 1
        
        # Risk scoring based on technique categories
        high_risk_techniques = ["T1190", "T1059", "T1078"]  # Exploitation, Command execution, Valid accounts
        medium_risk_techniques = ["T1021", "T1071"]  # Remote services, Application protocols
        
        score = 1
        for technique in techniques:
            if technique in high_risk_techniques:
                score += 3
            elif technique in medium_risk_techniques:
                score += 2
            else:
                score += 1
        
        return min(score, 10)  # Cap at 10
    
    def generate_attack_chain(self, findings: List[Dict]) -> Dict:
        """
        Generate an attack chain from security findings.
        
        Args:
            findings: List of findings with 'cve_id', 'service', 'description' keys
        
        Returns:
            Dict containing attack chain analysis
        """
        all_techniques = set()
        mapped_findings = []
        
        for finding in findings:
            cve_id = finding.get('cve_id', '')
            service = finding.get('service', '')
            
            # Map CVE to techniques
            cve_techniques = self.map_cve_to_techniques(cve_id)
            
            # Map service to techniques
            service_techniques = self.map_service_to_techniques(service)
            
            # Combine techniques
            techniques = list(set(cve_techniques + service_techniques))
            all_techniques.update(techniques)
            
            # Get technique details
            technique_details = []
            for technique_id in techniques:
                details = self.get_technique_details(technique_id)
                if details:
                    technique_details.append({
                        'id': technique_id,
                        'name': details.get('name', 'Unknown'),
                        'description': details.get('description', 'No description available')
                    })
            
            mapped_findings.append({
                'finding': finding,
                'techniques': technique_details,
                'technique_ids': techniques
            })
        
        # Get threat actors
        threat_actors = self.get_threat_actors(list(all_techniques))
        
        # Calculate overall risk score
        risk_score = self.calculate_risk_score(list(all_techniques))
        
        # Group by tactics
        tactics_analysis = {}
        for technique_id in all_techniques:
            details = self.get_technique_details(technique_id)
            if details and 'tactic' in details:
                tactic_id = details['tactic']
                tactic_details = self.get_tactic_details(tactic_id)
                if tactic_details:
                    if tactic_id not in tactics_analysis:
                        tactics_analysis[tactic_id] = {
                            'name': tactic_details.get('name', 'Unknown'),
                            'description': tactic_details.get('description', 'No description available'),
                            'techniques': []
                        }
                    tactics_analysis[tactic_id]['techniques'].append({
                        'id': technique_id,
                        'name': details.get('name', 'Unknown')
                    })
        
        return {
            'mapped_findings': mapped_findings,
            'all_techniques': list(all_techniques),
            'threat_actors': threat_actors,
            'risk_score': risk_score,
            'tactics_analysis': tactics_analysis,
            'attack_chain_summary': {
                'total_findings': len(findings),
                'total_techniques': len(all_techniques),
                'total_tactics': len(tactics_analysis),
                'threat_actor_count': len(threat_actors)
            }
        }

def enrich_findings_with_attack(findings: List[Dict], service: str = None) -> Dict:
    """
    Enrich security findings with MITRE ATT&CK framework analysis.
    
    Args:
        findings: List of findings (each with 'id', 'description' keys)
        service: Optional service name for additional context
    
    Returns:
        Dict containing ATT&CK analysis
    """
    mapper = MitreAttackMapper()
    
    # Convert findings to format expected by attack chain generator
    attack_findings = []
    for finding in findings:
        attack_findings.append({
            'cve_id': finding.get('id', ''),
            'service': service or 'unknown',
            'description': finding.get('description', '')
        })
    
    return mapper.generate_attack_chain(attack_findings)

# Example usage for developers
if __name__ == "__main__":
    print("=== Testing MITRE ATT&CK Integration ===")
    
    # Test with sample findings
    test_findings = [
        {"id": "CVE-2021-41773", "description": "Apache HTTP Server path traversal vulnerability"},
        {"id": "CVE-2021-42013", "description": "Apache HTTP Server remote code execution"},
        {"id": "CVE-2018-15473", "description": "SSH user enumeration vulnerability"}
    ]
    
    result = enrich_findings_with_attack(test_findings, "apache")
    
    print(f"\nRisk Score: {result['risk_score']}/10")
    print(f"Threat Actors: {', '.join(result['threat_actors'])}")
    print(f"Techniques Found: {', '.join(result['all_techniques'])}")
    
    print("\nTactics Analysis:")
    for tactic_id, tactic_info in result['tactics_analysis'].items():
        print(f"  {tactic_id} - {tactic_info['name']}")
        for technique in tactic_info['techniques']:
            print(f"    - {technique['id']}: {technique['name']}")
    
    print(f"\nAttack Chain Summary:")
    summary = result['attack_chain_summary']
    print(f"  Total Findings: {summary['total_findings']}")
    print(f"  Total Techniques: {summary['total_techniques']}")
    print(f"  Total Tactics: {summary['total_tactics']}")
    print(f"  Threat Actors: {summary['threat_actor_count']}") 