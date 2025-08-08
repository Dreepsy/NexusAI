# NexusAI API Reference

## Overview

This document provides a comprehensive reference for all the APIs, modules, classes, and functions available in NexusAI. It's organized by module and includes detailed information about parameters, return values, and usage examples.

## Table of Contents

1. [Core Modules](#core-modules)
2. [AI Engine](#ai-engine)
3. [Security System](#security-system)
4. [CLI Interface](#cli-interface)
5. [Web Interface](#web-interface)
6. [Monitoring System](#monitoring-system)
7. [Optimization System](#optimization-system)

## Core Modules

### Configuration Management

#### `nexus.core.config`

**Purpose**: Manages all configuration settings for NexusAI.

**Main Classes:**

##### `ConfigManager`

```python
class ConfigManager:
    def __init__(self, config_path: Optional[str] = None)
    def get_config(self) -> Dict[str, Any]
    def get_path(self, key: str) -> str
    def _create_default_config(self) -> None
    def _validate_config(self, config: Dict[str, Any]) -> bool
```

**Key Methods:**

- `get_config()`: Returns the complete configuration dictionary
- `get_path(key)`: Gets a specific configuration path
- `_create_default_config()`: Creates default configuration if none exists
- `_validate_config(config)`: Validates configuration structure

**Example Usage:**
```python
from nexus.core.config import get_config

# Get configuration
config = get_config()

# Access specific settings
ai_settings = config.get('ai', {})
security_settings = config.get('security', {})
```

### HTTP Client

#### `nexus.core.http_client`

**Purpose**: Handles HTTP requests with advanced features like retry logic and rate limiting.

**Main Classes:**

##### `HTTPClient`

```python
class HTTPClient:
    def __init__(self, timeout: int = 30, max_retries: int = 3)
    def get(self, url: str, headers: Optional[Dict] = None) -> Response
    def post(self, url: str, data: Optional[Dict] = None, headers: Optional[Dict] = None) -> Response
    def _make_request(self, method: str, url: str, **kwargs) -> Response
```

**Key Methods:**

- `get(url, headers)`: Performs GET request with optional headers
- `post(url, data, headers)`: Performs POST request with data and headers
- `_make_request(method, url, **kwargs)`: Internal method for making requests

**Example Usage:**
```python
from nexus.core.http_client import HTTPClient

client = HTTPClient(timeout=30, max_retries=3)
response = client.get("https://api.example.com/data")
```

### Main Application

#### `nexus.core.main`

**Purpose**: Main application entry point and orchestration.

**Main Functions:**

```python
def main() -> None
def setup_logging() -> None
def initialize_system() -> bool
def cleanup() -> None
```

**Example Usage:**
```python
from nexus.core.main import main

if __name__ == "__main__":
    main()
```

## AI Engine

### Real-time Learning

#### `nexus.ai.real_time_learning`

**Purpose**: Manages AI model training and prediction with real-time learning capabilities.

**Main Classes:**

##### `RealTimeLearning`

```python
class RealTimeLearning:
    def __init__(self, config: Optional[Dict] = None)
    def add_sample(self, features: Dict, prediction: int, actual: int) -> None
    def train_models(self) -> Dict[str, float]
    def predict(self, features: Dict) -> Tuple[int, float]
    def get_model_stats(self) -> Dict[str, Any]
    def save_models(self, path: str) -> None
    def load_models(self, path: str) -> None
```

**Key Methods:**

- `add_sample(features, prediction, actual)`: Adds new training sample
- `train_models()`: Trains all ensemble models
- `predict(features)`: Makes prediction with confidence score
- `get_model_stats()`: Returns model performance statistics
- `save_models(path)`: Saves trained models to disk
- `load_models(path)`: Loads models from disk

**Example Usage:**
```python
from nexus.ai.real_time_learning import RealTimeLearning

# Initialize learning system
learner = RealTimeLearning()

# Add training data
learner.add_sample(
    features={'port_count': 5, 'open_ports': [22, 80, 443]},
    prediction=1,
    actual=1
)

# Train models
accuracy = learner.train_models()

# Make prediction
prediction, confidence = learner.predict({'port_count': 3, 'open_ports': [22, 80]})
```

### Advanced Threat Intelligence

#### `nexus.ai.advanced_threat_intel`

**Purpose**: Aggregates threat intelligence from multiple sources.

**Main Classes:**

##### `AdvancedThreatIntel`

```python
class AdvancedThreatIntel:
    def __init__(self, config: Optional[Dict] = None)
    def analyze_ip(self, ip: str) -> Dict[str, Any]
    def search_assets(self, query: str, limit: int = 10) -> List[Dict]
    def get_vulnerability_info(self, cve_id: str) -> Dict[str, Any]
    def generate_report(self, target_data: Dict) -> str
    def _fetch_virustotal_data(self, target: str) -> Dict[str, Any]
    def _fetch_shodan_data(self, query: str) -> List[Dict]
```

**Key Methods:**

- `analyze_ip(ip)`: Analyzes IP address for threats
- `search_assets(query, limit)`: Searches for internet assets
- `get_vulnerability_info(cve_id)`: Gets CVE information
- `generate_report(target_data)`: Generates comprehensive threat report

**Example Usage:**
```python
from nexus.ai.advanced_threat_intel import AdvancedThreatIntel

# Initialize threat intelligence
threat_intel = AdvancedThreatIntel()

# Analyze IP
results = threat_intel.analyze_ip("192.168.1.1")

# Search for assets
assets = threat_intel.search_assets("apache", limit=5)

# Generate report
report = threat_intel.generate_report({'ip': '192.168.1.1'})
```

### MITRE ATT&CK Integration

#### `nexus.ai.mitre_attack`

**Purpose**: Maps security findings to MITRE ATT&CK framework.

**Main Classes:**

##### `MITREAttackMapper`

```python
class MITREAttackMapper:
    def __init__(self)
    def map_findings(self, scan_results: Dict) -> List[Dict]
    def get_technique_info(self, technique_id: str) -> Dict[str, Any]
    def get_tactic_info(self, tactic_id: str) -> Dict[str, Any]
    def calculate_risk_score(self, findings: List[Dict]) -> float
```

**Key Methods:**

- `map_findings(scan_results)`: Maps scan results to ATT&CK techniques
- `get_technique_info(technique_id)`: Gets detailed technique information
- `get_tactic_info(tactic_id)`: Gets tactic information
- `calculate_risk_score(findings)`: Calculates overall risk score

**Example Usage:**
```python
from nexus.ai.mitre_attack import MITREAttackMapper

mapper = MITREAttackMapper()

# Map findings to ATT&CK
findings = mapper.map_findings(scan_results)

# Calculate risk score
risk_score = mapper.calculate_risk_score(findings)
```

### Exploit Developer

#### `nexus.ai.exploit_developer`

**Purpose**: Generates detailed exploitation guides for vulnerabilities.

**Main Classes:**

##### `ExploitDeveloper`

```python
class ExploitDeveloper:
    def __init__(self, config: Optional[Dict] = None)
    def generate_exploit_guide(self, scan_results: Dict) -> str
    def identify_vulnerabilities(self, scan_data: Dict) -> List[Dict]
    def create_exploit_methods(self, vulnerabilities: List[Dict]) -> List[Dict]
    def generate_quick_commands(self, exploits: List[Dict]) -> str
```

**Key Methods:**

- `generate_exploit_guide(scan_results)`: Generates complete exploitation guide
- `identify_vulnerabilities(scan_data)`: Identifies vulnerabilities in scan data
- `create_exploit_methods(vulnerabilities)`: Creates exploitation methods
- `generate_quick_commands(exploits)`: Generates quick exploit commands

**Example Usage:**
```python
from nexus.ai.exploit_developer import ExploitDeveloper

developer = ExploitDeveloper()

# Generate exploitation guide
guide = developer.generate_exploit_guide(scan_results)
```

### DeepSeek Integration

#### `nexus.ai.deepseek_integration`

**Purpose**: Integrates with DeepSeek AI for advanced analysis.

**Main Classes:**

##### `DeepSeekIntegration`

```python
class DeepSeekIntegration:
    def __init__(self, api_key: Optional[str] = None)
    def analyze_vulnerabilities(self, scan_data: Dict) -> str
    def generate_summary(self, findings: List[Dict]) -> str
    def _make_api_request(self, prompt: str) -> str
```

**Key Methods:**

- `analyze_vulnerabilities(scan_data)`: Analyzes vulnerabilities using DeepSeek
- `generate_summary(findings)`: Generates summary of findings
- `_make_api_request(prompt)`: Makes API request to DeepSeek

**Example Usage:**
```python
from nexus.ai.deepseek_integration import DeepSeekIntegration

deepseek = DeepSeekIntegration(api_key="your_api_key")

# Analyze vulnerabilities
analysis = deepseek.analyze_vulnerabilities(scan_data)

# Generate summary
summary = deepseek.generate_summary(findings)
```

### Threat Feeds

#### `nexus.ai.threat_feeds`

**Purpose**: Manages threat intelligence feeds from various sources.

**Main Classes:**

##### `ThreatFeedManager`

```python
class ThreatFeedManager:
    def __init__(self, config: Optional[Dict] = None)
    def fetch_virustotal_data(self, target: str) -> Dict[str, Any]
    def fetch_shodan_data(self, query: str) -> List[Dict]
    def fetch_abuseipdb_data(self, ip: str) -> Dict[str, Any]
    def fetch_otx_data(self, indicator: str) -> Dict[str, Any]
```

**Key Methods:**

- `fetch_virustotal_data(target)`: Fetches data from VirusTotal
- `fetch_shodan_data(query)`: Fetches data from Shodan
- `fetch_abuseipdb_data(ip)`: Fetches data from AbuseIPDB
- `fetch_otx_data(indicator)`: Fetches data from OTX

**Example Usage:**
```python
from nexus.ai.threat_feeds import ThreatFeedManager

feeds = ThreatFeedManager()

# Fetch threat data
vt_data = feeds.fetch_virustotal_data("example.com")
shodan_data = feeds.fetch_shodan_data("apache")
```

### CVE Fetcher

#### `nexus.ai.vuln_cve_fetcher`

**Purpose**: Fetches and manages CVE vulnerability data.

**Main Classes:**

##### `CVEFetcher`

```python
class CVEFetcher:
    def __init__(self)
    def fetch_cve_info(self, cve_id: str) -> Dict[str, Any]
    def search_cves(self, query: str) -> List[Dict]
    def get_cve_by_product(self, product: str) -> List[Dict]
```

**Key Methods:**

- `fetch_cve_info(cve_id)`: Fetches specific CVE information
- `search_cves(query)`: Searches for CVEs by query
- `get_cve_by_product(product)`: Gets CVEs for specific product

**Example Usage:**
```python
from nexus.ai.vuln_cve_fetcher import CVEFetcher

fetcher = CVEFetcher()

# Fetch CVE information
cve_info = fetcher.fetch_cve_info("CVE-2021-44228")

# Search for CVEs
cves = fetcher.search_cves("apache")
```

## Security System

### Enhanced Security Validator

#### `nexus.security.security_validator_enhanced`

**Purpose**: Validates inputs and prevents security vulnerabilities.

**Main Classes:**

##### `EnhancedSecurityValidator`

```python
class EnhancedSecurityValidator:
    def __init__(self, config: Optional[Dict] = None)
    def validate_ip(self, ip: str) -> bool
    def validate_file_path(self, path: str) -> bool
    def validate_url(self, url: str) -> bool
    def validate_xml(self, xml_content: str) -> bool
    def validate_api_key(self, key: str, service: str) -> bool
    def sanitize_input(self, input_data: str) -> str
```

**Key Methods:**

- `validate_ip(ip)`: Validates IP address format
- `validate_file_path(path)`: Validates file path for security
- `validate_url(url)`: Validates URL format and safety
- `validate_xml(xml_content)`: Validates XML content
- `validate_api_key(key, service)`: Validates API key format
- `sanitize_input(input_data)`: Sanitizes user input

**Example Usage:**
```python
from nexus.security.security_validator_enhanced import EnhancedSecurityValidator

validator = EnhancedSecurityValidator()

# Validate inputs
is_valid_ip = validator.validate_ip("192.168.1.1")
is_valid_path = validator.validate_file_path("/safe/path/file.xml")
sanitized_input = validator.sanitize_input(user_input)
```

## CLI Interface

### Command Parser

#### `nexus.cli.parser`

**Purpose**: Handles command-line argument parsing.

**Main Functions:**

```python
def create_parser() -> ArgumentParser
def parse_arguments() -> Namespace
def validate_args(args: Namespace) -> bool
```

**Example Usage:**
```python
from nexus.cli.parser import create_parser, parse_arguments

# Create and parse arguments
parser = create_parser()
args = parse_arguments()
```

### Command Handler

#### `nexus.cli.commands`

**Purpose**: Implements CLI command functionality.

**Main Functions:**

```python
def main() -> None
def analyze_network_scan(scan_path: str, output_format: str = "text", include_exploitation_guide: bool = False) -> str
def check_ip_reputation(ips: List[str]) -> str
def search_internet_assets(query: str, limit: int = 10) -> str
def get_learning_stats() -> str
def run_health_check() -> str
```

**Key Functions:**

- `main()`: Main CLI entry point
- `analyze_network_scan(scan_path, output_format, include_exploitation_guide)`: Analyzes network scan
- `check_ip_reputation(ips)`: Checks IP reputation
- `search_internet_assets(query, limit)`: Searches for internet assets
- `get_learning_stats()`: Gets AI learning statistics
- `run_health_check()`: Runs system health check

**Example Usage:**
```python
from nexus.cli.commands import analyze_network_scan

# Analyze network scan
result = analyze_network_scan("scan.xml", "json", True)
```

## Web Interface

### Flask Application

#### `nexus.web.app`

**Purpose**: Provides web-based interface for NexusAI.

**Main Classes:**

##### `NexusAIWebApp`

```python
class NexusAIWebApp:
    def __init__(self)
    def create_app(self) -> Flask
    def setup_routes(self) -> None
    def setup_socketio(self) -> None
```

**Key Routes:**

- `GET /`: Main dashboard
- `POST /api/analyze`: Analyze scan file
- `GET /api/health`: Health check endpoint
- `GET /api/stats`: Get system statistics

**Example Usage:**
```python
from nexus.web.app import NexusAIWebApp

app = NexusAIWebApp()
flask_app = app.create_app()

if __name__ == "__main__":
    flask_app.run(debug=True)
```

## Monitoring System

### Health Monitor

#### `nexus.monitoring.health_check`

**Purpose**: Monitors system health and performance.

**Main Classes:**

##### `HealthMonitor`

```python
class HealthMonitor:
    def __init__(self)
    def check_system_resources(self) -> Dict[str, Any]
    def check_ai_models(self) -> Dict[str, Any]
    def check_api_health(self) -> Dict[str, Any]
    def check_cache_performance(self) -> Dict[str, Any]
    def generate_health_report(self) -> str
```

**Key Methods:**

- `check_system_resources()`: Checks CPU, memory, disk usage
- `check_ai_models()`: Checks AI model status
- `check_api_health()`: Checks external API health
- `check_cache_performance()`: Checks cache performance
- `generate_health_report()`: Generates comprehensive health report

**Example Usage:**
```python
from nexus.monitoring.health_check import HealthMonitor

monitor = HealthMonitor()

# Check system health
health_report = monitor.generate_health_report()

# Check specific components
resources = monitor.check_system_resources()
models = monitor.check_ai_models()
```

## Optimization System

### Cache Manager

#### `nexus.optimization.cache_manager`

**Purpose**: Manages intelligent caching for improved performance.

**Main Classes:**

##### `CacheManager`

```python
class CacheManager:
    def __init__(self, config: Optional[Dict] = None)
    def get(self, key: str, namespace: str = "default") -> Optional[Any]
    def set(self, key: str, value: Any, ttl: int = 3600, namespace: str = "default") -> None
    def delete(self, key: str, namespace: str = "default") -> None
    def clear_namespace(self, namespace: str) -> None
    def get_stats(self) -> Dict[str, Any]
    def cleanup_expired(self) -> int
```

**Key Methods:**

- `get(key, namespace)`: Gets cached value
- `set(key, value, ttl, namespace)`: Sets cached value
- `delete(key, namespace)`: Deletes cached value
- `clear_namespace(namespace)`: Clears entire namespace
- `get_stats()`: Gets cache statistics
- `cleanup_expired()`: Removes expired cache entries

**Example Usage:**
```python
from nexus.optimization.cache_manager import CacheManager

cache = CacheManager()

# Cache data
cache.set("scan_result", scan_data, ttl=3600, namespace="scans")

# Retrieve cached data
result = cache.get("scan_result", namespace="scans")

# Get cache statistics
stats = cache.get_stats()
```

## Error Handling

### Common Exceptions

```python
class NexusAIError(Exception):
    """Base exception for NexusAI"""
    pass

class ConfigurationError(NexusAIError):
    """Configuration-related errors"""
    pass

class ValidationError(NexusAIError):
    """Input validation errors"""
    pass

class APIError(NexusAIError):
    """External API errors"""
    pass

class ModelError(NexusAIError):
    """AI model errors"""
    pass
```

### Error Handling Patterns

```python
try:
    result = analyze_network_scan("scan.xml")
except ValidationError as e:
    print(f"Validation error: {e}")
except APIError as e:
    print(f"API error: {e}")
except NexusAIError as e:
    print(f"General error: {e}")
```

## Logging

### Logging Configuration

```python
import logging
from nexus.core.config import get_config

# Configure logging
config = get_config()
logging.basicConfig(
    level=config.get('logging', {}).get('level', 'INFO'),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Get logger for specific module
logger = logging.getLogger('nexus.ai.real_time_learning')
```

### Logging Levels

- **DEBUG**: Detailed information for debugging
- **INFO**: General information about program execution
- **WARNING**: Warning messages for potential issues
- **ERROR**: Error messages for handled exceptions
- **CRITICAL**: Critical errors that may prevent operation

## Testing

### Unit Testing

```python
import pytest
from nexus.ai.real_time_learning import RealTimeLearning

def test_real_time_learning():
    learner = RealTimeLearning()
    
    # Test adding sample
    learner.add_sample({'port_count': 5}, 1, 1)
    
    # Test prediction
    prediction, confidence = learner.predict({'port_count': 3})
    assert isinstance(prediction, int)
    assert isinstance(confidence, float)
```

### Integration Testing

```python
import pytest
from nexus.cli.commands import analyze_network_scan

def test_scan_analysis():
    # Test scan analysis
    result = analyze_network_scan("test_scan.xml")
    assert "AI PREDICTION" in result
    assert "THREAT INTELLIGENCE" in result
```

## Performance Optimization

### Caching Best Practices

```python
# Use appropriate TTL for different data types
cache.set("api_response", data, ttl=300)  # 5 minutes for API data
cache.set("model_prediction", prediction, ttl=3600)  # 1 hour for predictions
cache.set("static_data", data, ttl=86400)  # 24 hours for static data
```

### Memory Management

```python
# Clear large objects when done
del large_dataset

# Use generators for large datasets
def process_large_dataset():
    for item in large_dataset:
        yield process_item(item)
```

## Security Best Practices

### Input Validation

```python
from nexus.security.security_validator_enhanced import EnhancedSecurityValidator

validator = EnhancedSecurityValidator()

# Always validate user input
if not validator.validate_ip(user_ip):
    raise ValidationError("Invalid IP address")

# Sanitize user input
sanitized_input = validator.sanitize_input(user_input)
```

### API Key Management

```python
import os
from nexus.core.config import get_config

# Use environment variables for API keys
config = get_config()
api_key = os.getenv('VIRUSTOTAL_API_KEY') or config.get('security', {}).get('api_keys', {}).get('virustotal')

if not api_key:
    raise ConfigurationError("VirusTotal API key not found")
```

## Conclusion

This API reference provides comprehensive documentation for all the modules, classes, and functions available in NexusAI. The modular design allows for easy integration and extension, while the comprehensive error handling and logging ensure reliable operation.

For more detailed information about specific components, refer to the individual module documentation and source code comments.
