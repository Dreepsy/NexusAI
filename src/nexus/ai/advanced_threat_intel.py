"""
Advanced Threat Intelligence Module
Provides comprehensive threat intelligence gathering and analysis capabilities with humanized insights

TODO: The rate limiting is a bit aggressive, need to tune it
TODO: Sometimes the API responses are malformed, need better error handling
TODO: The cache invalidation could be smarter
"""

import json
import os
import time
import asyncio
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
import ipaddress
from dataclasses import dataclass
from enum import Enum

from ..core.config import get_config, get_logger
from ..core.http_client import get_http_client
from ..security.security_validator_enhanced import get_security_validator
from ..optimization.cache_manager import get_cache_manager

class ThreatLevel(Enum):
    """Enumeration for threat levels with humanized descriptions"""
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ThreatIndicator:
    """Data class for threat indicators with enhanced metadata"""
    ip: str
    threat_level: ThreatLevel
    reputation_score: float
    confidence: float
    sources: List[str]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    tags: List[str]
    description: str
    recommendations: List[str]

class AdvancedThreatIntel:
    """
    Advanced Threat Intelligence class that aggregates data from multiple sources
    with sophisticated analysis and humanized insights
    """
    
    def __init__(self):
        self.config = get_config()
        self.logger = get_logger()
        self.http_client = get_http_client()
        self.security_validator = get_security_validator()
        self.cache_manager = get_cache_manager()
        
        # Get API keys from environment
        self.virustotal_api_key = self.config.get_api_key('virustotal')
        self.shodan_api_key = self.config.get_api_key('shodan')
        self.abuseipdb_api_key = self.config.get_api_key('abuseipdb')
        self.otx_api_key = self.config.get_api_key('otx')
        
        # Initialize threat intelligence sources
        self.threat_sources = self._initialize_threat_sources()
        
        # Threat intelligence cache settings
        self.cache_ttl = self.config.get('performance.cache_ttl', 3600)
        
        self.logger.info("AdvancedThreatIntel initialized", 
                        sources=len(self.threat_sources),
                        cache_ttl=self.cache_ttl)
        
        # Check if we have enough API keys configured
        configured_sources = sum(1 for source in self.threat_sources.values() if source['enabled'])
        if configured_sources < 2:
            self.logger.warning(f"Only {configured_sources} threat intelligence sources configured. Results may be limited.")
            # TODO: Should probably add a way to get free API keys automatically
    
    def _initialize_threat_sources(self) -> Dict[str, Dict[str, Any]]:
        """Initialize threat intelligence sources with configuration"""
        sources = {
            'virustotal': {
                'enabled': bool(self.virustotal_api_key),
                'api_key': self.virustotal_api_key,
                'rate_limit': self.config.get('threat_intelligence.virustotal.rate_limit', 4),
                'base_url': 'https://www.virustotal.com/vtapi/v2',
                'timeout': 30
            },
            'shodan': {
                'enabled': bool(self.shodan_api_key),
                'api_key': self.shodan_api_key,
                'rate_limit': self.config.get('threat_intelligence.shodan.rate_limit', 1),
                'base_url': 'https://api.shodan.io',
                'timeout': 30
            },
            'abuseipdb': {
                'enabled': bool(self.abuseipdb_api_key),
                'api_key': self.abuseipdb_api_key,
                'base_url': 'https://api.abuseipdb.com/api/v2',
                'timeout': 30
            },
            'otx': {
                'enabled': bool(self.otx_api_key),
                'api_key': self.otx_api_key,
                'base_url': 'https://otx.alienvault.com/api/v1',
                'timeout': 30
            }
        }
        
        return sources
    
    def aggregate_threat_feeds(self, ips: List[str]) -> Dict[str, Any]:
        """
        Aggregate threat intelligence from multiple sources for given IPs
        with enhanced analysis and humanized insights
        
        Args:
            ips: List of IP addresses to check
            
        Returns:
            Dictionary containing comprehensive threat intelligence results
        """
        # Validate and sanitize input
        validated_ips = []
        for ip in ips:
            validation = self.security_validator.validate_and_sanitize_input(ip, "ip")
            if validation['valid']:
                validated_ips.append(ip)
            else:
                self.logger.warning("Invalid IP address", ip=ip, errors=validation['errors'])
        
        if not validated_ips:
            return self._create_empty_result("No valid IP addresses provided")
        
        # Check cache first
        cache_key = f"threat_intel_{hash(tuple(sorted(validated_ips)))}"
        cached_result = self.cache_manager.get(cache_key, namespace="threat_intel")
        if cached_result:
            self.logger.info("Using cached threat intelligence results")
            return cached_result
        
        # Initialize results structure
        results = {
            "summary": {
                "total_indicators": len(validated_ips),
                "malicious_count": 0,
                "suspicious_count": 0,
                "clean_count": 0,
                "analysis_time": datetime.now().isoformat(),
                "sources_checked": []
            },
            "indicators": {},
            "insights": [],
            "recommendations": []
        }
        
        # Process each IP with enhanced analysis
        for ip in validated_ips:
            self.logger.info("Analyzing IP", ip=ip)
            ip_results = self._analyze_single_ip(ip)
            results["indicators"][ip] = ip_results
            
            # Update summary statistics
            threat_level = ip_results.get('threat_level', 'unknown')
            if threat_level in ['malicious', 'critical']:
                results["summary"]["malicious_count"] += 1
            elif threat_level in ['suspicious', 'medium']:
                results["summary"]["suspicious_count"] += 1
            else:
                results["summary"]["clean_count"] += 1
        
        # Generate insights and recommendations
        results["insights"] = self._generate_insights(results)
        results["recommendations"] = self._generate_recommendations(results)
        
        # Cache the results
        self.cache_manager.set(cache_key, results, ttl=self.cache_ttl, namespace="threat_intel")
        
        return results
    
    def _analyze_single_ip(self, ip: str) -> Dict[str, Any]:
        """
        Analyze a single IP against all threat intelligence sources
        with sophisticated scoring and humanized assessment
        
        Args:
            ip: IP address to analyze
            
        Returns:
            Dictionary with comprehensive threat intelligence results
        """
        result = {
            "ip": ip,
            "threat_level": "unknown",
            "reputation_score": 0.0,
            "confidence": 0.0,
            "sources_checked": [],
            "first_seen": None,
            "last_seen": None,
            "tags": [],
            "description": "",
            "virustotal": {"error": "API key not configured"},
            "shodan": {"error": "API key not configured"},
            "abuseipdb": {"error": "API key not configured"},
            "otx": {"error": "API key not configured"}
        }
        
        # Check VirusTotal
        if self.threat_sources['virustotal']['enabled']:
            vt_result = self._check_virustotal(ip)
            result["virustotal"] = vt_result
            result["sources_checked"].append("virustotal")
            
            # Update threat assessment based on VirusTotal
            if vt_result.get("detection_ratio", 0) > 0.1:
                result["threat_level"] = "malicious"
                result["reputation_score"] = 10.0
            elif vt_result.get("detection_ratio", 0) > 0.05:
                result["threat_level"] = "suspicious"
                result["reputation_score"] = 30.0
        
        # Check Shodan
        if self.threat_sources['shodan']['enabled']:
            shodan_result = self._check_shodan(ip)
            result["shodan"] = shodan_result
            result["sources_checked"].append("shodan")
            
            # Update assessment based on Shodan data
            if shodan_result.get("ports", []):
                open_ports = len(shodan_result["ports"])
                if open_ports > 10:
                    result["threat_level"] = max(result["threat_level"], "suspicious")
                    result["reputation_score"] = max(result["reputation_score"], 40.0)
        
        # Check AbuseIPDB
        if self.threat_sources['abuseipdb']['enabled']:
            abuse_result = self._check_abuseipdb(ip)
            result["abuseipdb"] = abuse_result
            result["sources_checked"].append("abuseipdb")
            
            # Update assessment based on AbuseIPDB
            abuse_score = abuse_result.get("abuse_confidence_score", 0)
            if abuse_score > 80:
                result["threat_level"] = "malicious"
                result["reputation_score"] = max(result["reputation_score"], 80.0)
            elif abuse_score > 50:
                result["threat_level"] = max(result["threat_level"], "suspicious")
                result["reputation_score"] = max(result["reputation_score"], 60.0)
        
        # Check OTX
        if self.threat_sources['otx']['enabled']:
            otx_result = self._check_otx(ip)
            result["otx"] = otx_result
            result["sources_checked"].append("otx")
            
            # Update assessment based on OTX
            pulse_count = otx_result.get("pulse_count", 0)
            if pulse_count > 5:
                result["threat_level"] = "malicious"
                result["reputation_score"] = max(result["reputation_score"], 70.0)
            elif pulse_count > 1:
                result["threat_level"] = max(result["threat_level"], "suspicious")
                result["reputation_score"] = max(result["reputation_score"], 50.0)
        
        # Calculate final confidence score
        sources_checked = len(result["sources_checked"])
        if sources_checked > 0:
            result["confidence"] = min(1.0, sources_checked / 4.0)
        
        # Generate humanized description
        result["description"] = self._generate_threat_description(result)
        
        # Add tags based on findings
        result["tags"] = self._generate_threat_tags(result)
        
        return result
    
    def _check_virustotal(self, ip: str) -> Dict[str, Any]:
        """Check IP against VirusTotal with enhanced error handling"""
        try:
            if not self.virustotal_api_key:
                return {"error": "API key not configured"}
            
            url = f"{self.threat_sources['virustotal']['base_url']}/ip-address/report"
            params = {
                'apikey': self.virustotal_api_key,
                'ip': ip
            }
            
            response = self.http_client.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "detection_ratio": data.get("positives", 0) / max(data.get("total", 1), 1),
                    "total_scanners": data.get("total", 0),
                    "positives": data.get("positives", 0),
                    "country": data.get("country", "Unknown"),
                    "as_owner": data.get("as_owner", "Unknown"),
                    "last_analysis_date": data.get("last_analysis_date")
                }
            else:
                return {"error": f"API request failed: {response.status_code}"}
                
        except Exception as e:
            self.logger.error("VirusTotal check failed", ip=ip, error=str(e))
            return {"error": str(e)}
    
    def _check_shodan(self, ip: str) -> Dict[str, Any]:
        """Check IP against Shodan with enhanced data processing"""
        try:
            if not self.shodan_api_key:
                return {"error": "API key not configured"}
            
            url = f"{self.threat_sources['shodan']['base_url']}/shodan/host/{ip}"
            params = {
                'key': self.shodan_api_key
            }
            
            response = self.http_client.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "ports": data.get("ports", []),
                    "hostnames": data.get("hostnames", []),
                    "country_name": data.get("country_name", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "org": data.get("org", "Unknown"),
                    "os": data.get("os", "Unknown"),
                    "last_update": data.get("last_update")
                }
            else:
                return {"error": f"API request failed: {response.status_code}"}
                
        except Exception as e:
            self.logger.error("Shodan check failed", ip=ip, error=str(e))
            return {"error": str(e)}
    
    def _check_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Check IP against AbuseIPDB with enhanced scoring"""
        try:
            if not self.abuseipdb_api_key:
                return {"error": "API key not configured"}
            
            url = f"{self.threat_sources['abuseipdb']['base_url']}/check"
            params = {
                'ipAddress': ip,
                'maxAgeInDays': '90'
            }
            headers = {
                'Accept': 'application/json',
                'Key': self.abuseipdb_api_key
            }
            
            response = self.http_client.get(url, params=params, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "abuse_confidence_score": data.get("data", {}).get("abuseConfidenceScore", 0),
                    "country_code": data.get("data", {}).get("countryCode", "Unknown"),
                    "usage_type": data.get("data", {}).get("usageType", "Unknown"),
                    "is_public": data.get("data", {}).get("isPublic", False),
                    "is_tor_exit_node": data.get("data", {}).get("isTorExitNode", False),
                    "total_reports": data.get("data", {}).get("totalReports", 0)
                }
            else:
                return {"error": f"API request failed: {response.status_code}"}
                
        except Exception as e:
            self.logger.error("AbuseIPDB check failed", ip=ip, error=str(e))
            return {"error": str(e)}
    
    def _check_otx(self, ip: str) -> Dict[str, Any]:
        """Check IP against OTX with enhanced threat context"""
        try:
            if not self.otx_api_key:
                return {"error": "API key not configured"}
            
            url = f"{self.threat_sources['otx']['base_url']}/indicators/IPv4/{ip}/general"
            headers = {
                'X-OTX-API-KEY': self.otx_api_key
            }
            
            response = self.http_client.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "country_name": data.get("country_name", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "asn": data.get("asn", "Unknown"),
                    "reputation": data.get("reputation", 0),
                    "base_indicator": data.get("base_indicator", {}),
                    "sections": list(data.keys())
                }
            else:
                return {"error": f"API request failed: {response.status_code}"}
                
        except Exception as e:
            self.logger.error("OTX check failed", ip=ip, error=str(e))
            return {"error": str(e)}
    
    def search_internet_assets(self, query: str) -> Dict[str, Any]:
        """Search for internet assets using Shodan with enhanced filtering"""
        try:
            if not self.shodan_api_key:
                return {"error": "Shodan API key not configured"}
            
            # Validate query
            validation = self.security_validator.validate_and_sanitize_input(query, "text")
            if not validation['valid']:
                return {"error": f"Invalid query: {validation['errors']}"}
            
            # Check cache
            cache_key = f"shodan_search_{hash(query)}"
            cached_result = self.cache_manager.get(cache_key, namespace="shodan")
            if cached_result:
                return cached_result
            
            url = f"{self.threat_sources['shodan']['base_url']}/shodan/host/search"
            params = {
                'key': self.shodan_api_key,
                'query': query,
                'facets': '{"country": 10, "port": 10}',
                'limit': 100
            }
            
            response = self.http_client.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                result = {
                    "query": query,
                    "total": data.get("total", 0),
                    "matches": [],
                    "facets": data.get("facets", {}),
                    "search_time": datetime.now().isoformat()
                }
                
                # Process matches with enhanced data
                for match in data.get("matches", []):
                    processed_match = {
                        "ip": match.get("ip_str", "Unknown"),
                        "port": match.get("port", "Unknown"),
                        "product": match.get("product", "Unknown"),
                        "version": match.get("version", ""),
                        "org": match.get("org", "Unknown"),
                        "location": {
                            "city": match.get("location", {}).get("city", "Unknown"),
                            "country_name": match.get("location", {}).get("country_name", "Unknown"),
                            "latitude": match.get("location", {}).get("latitude"),
                            "longitude": match.get("location", {}).get("longitude")
                        },
                        "hostnames": match.get("hostnames", []),
                        "tags": match.get("tags", []),
                        "timestamp": match.get("timestamp", ""),
                        "data": match.get("data", "")[:200] + "..." if len(match.get("data", "")) > 200 else match.get("data", "")
                    }
                    result["matches"].append(processed_match)
                
                # Cache the result
                self.cache_manager.set(cache_key, result, ttl=self.cache_ttl, namespace="shodan")
                
                return result
            else:
                return {"error": f"API request failed: {response.status_code}"}
                
        except Exception as e:
            self.logger.error("Shodan search failed", query=query, error=str(e))
            return {"error": str(e)}
    
    def _generate_threat_description(self, result: Dict[str, Any]) -> str:
        """Generate humanized threat description"""
        threat_level = result.get("threat_level", "unknown")
        reputation_score = result.get("reputation_score", 0)
        
        if threat_level == "malicious":
            return f"This IP has been flagged as malicious by multiple threat intelligence sources with a reputation score of {reputation_score:.1f}%."
        elif threat_level == "suspicious":
            return f"This IP shows suspicious activity patterns with a reputation score of {reputation_score:.1f}%."
        elif threat_level == "clean":
            return f"This IP appears to be clean with a good reputation score of {reputation_score:.1f}%."
        else:
            return f"This IP has limited threat intelligence data available."
    
    def _generate_threat_tags(self, result: Dict[str, Any]) -> List[str]:
        """Generate threat tags based on analysis results"""
        tags = []
        
        # Add tags based on threat level
        threat_level = result.get("threat_level", "unknown")
        if threat_level == "malicious":
            tags.extend(["malicious", "high-risk", "blocked"])
        elif threat_level == "suspicious":
            tags.extend(["suspicious", "medium-risk", "monitor"])
        elif threat_level == "clean":
            tags.extend(["clean", "low-risk", "trusted"])
        
        # Add tags based on sources
        sources = result.get("sources_checked", [])
        if "virustotal" in sources:
            tags.append("virustotal-checked")
        if "shodan" in sources:
            tags.append("shodan-checked")
        if "abuseipdb" in sources:
            tags.append("abuseipdb-checked")
        if "otx" in sources:
            tags.append("otx-checked")
        
        # Add tags based on specific findings
        if result.get("virustotal", {}).get("positives", 0) > 0:
            tags.append("virus-detected")
        if result.get("abuseipdb", {}).get("is_tor_exit_node", False):
            tags.append("tor-exit-node")
        
        return tags
    
    def _generate_insights(self, results: Dict[str, Any]) -> List[str]:
        """Generate humanized insights from threat intelligence analysis"""
        insights = []
        summary = results.get("summary", {})
        
        total = summary.get("total_indicators", 0)
        malicious = summary.get("malicious_count", 0)
        suspicious = summary.get("suspicious_count", 0)
        
        if total > 0:
            threat_percentage = ((malicious + suspicious) / total) * 100
            insights.append(f"Threat Level: {threat_percentage:.1f}% of analyzed IPs show concerning activity")
        
        if malicious > 0:
            insights.append(f"🚨 {malicious} IPs flagged as malicious by threat intelligence sources")
        
        if suspicious > 0:
            insights.append(f"⚠️ {suspicious} IPs show suspicious activity patterns")
        
        # Add source-specific insights
        sources_used = set()
        for indicator in results.get("indicators", {}).values():
            sources_used.update(indicator.get("sources_checked", []))
        
        if len(sources_used) >= 3:
            insights.append("✅ Comprehensive threat intelligence analysis performed")
        elif len(sources_used) >= 1:
            insights.append("⚠️ Limited threat intelligence data available")
        else:
            insights.append("❌ No threat intelligence sources available")
        
        return insights
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate actionable security recommendations"""
        recommendations = []
        summary = results.get("summary", {})
        
        malicious = summary.get("malicious_count", 0)
        suspicious = summary.get("suspicious_count", 0)
        
        if malicious > 0:
            recommendations.append("🚨 Immediately block all malicious IPs identified")
            recommendations.append("🔍 Investigate the source and purpose of malicious activity")
        
        if suspicious > 0:
            recommendations.append("⚠️ Monitor suspicious IPs closely for further activity")
            recommendations.append("📊 Implement additional logging for suspicious IPs")
        
        if malicious + suspicious > 0:
            recommendations.append("🛡️ Review and update firewall rules based on findings")
            recommendations.append("📈 Consider implementing threat intelligence feeds")
        
        recommendations.append("🔄 Regularly update threat intelligence sources")
        recommendations.append("📋 Document all findings for compliance and audit purposes")
        
        return recommendations
    
    def _create_empty_result(self, message: str) -> Dict[str, Any]:
        """Create an empty result structure with message"""
        return {
            "summary": {
                "total_indicators": 0,
                "malicious_count": 0,
                "suspicious_count": 0,
                "clean_count": 0,
                "analysis_time": datetime.now().isoformat(),
                "sources_checked": []
            },
            "indicators": {},
            "insights": [message],
            "recommendations": ["Please provide valid IP addresses for analysis"]
        } 