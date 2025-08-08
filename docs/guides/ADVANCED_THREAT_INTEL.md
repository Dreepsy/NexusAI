# Advanced Threat Intelligence for NEXUS-AI

This module provides comprehensive threat intelligence capabilities for NEXUS-AI, integrating multiple threat feeds and analysis tools to provide deep insights into potential security threats.

## 🚀 Features

### 1. VirusTotal Integration
- **File Analysis**: Check file hashes against VirusTotal's database
- **URL Analysis**: Analyze URLs for malicious activity
- **IP Reputation**: Check IP addresses for known malicious activity
- **Real-time Detection**: Get detection ratios from 70+ antivirus engines

### 2. Shodan Integration
- **Internet Asset Discovery**: Find internet-facing assets and services
- **Vulnerability Assessment**: Identify open ports and potential vulnerabilities
- **Geographic Analysis**: Map asset locations and organizations
- **Service Fingerprinting**: Identify running services and versions

### 3. Custom Threat Feed Aggregation
- **Multi-source Analysis**: Combine data from multiple threat feeds
- **Reputation Scoring**: Calculate threat scores based on multiple factors
- **Risk Assessment**: Determine threat levels (low/medium/high)
- **Comprehensive Reporting**: Generate detailed threat intelligence reports

## 🔧 Setup

### 1. API Key Configuration

#### VirusTotal API Key
1. Sign up at [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Get your API key from your account settings
3. Set the environment variable:
   ```bash
   export VIRUSTOTAL_API_KEY="your_api_key_here"
   ```

#### Shodan API Key
1. Sign up at [Shodan](https://account.shodan.io/register)
2. Get your API key from your account dashboard
3. Set the environment variable:
   ```bash
   export SHODAN_API_KEY="your_api_key_here"
   ```

### 2. Configuration File
Update your `config.yaml` to include threat intelligence settings:

```yaml
threat_intelligence:
  virustotal:
    api_key: null  # Set via environment variable
    base_url: "https://www.virustotal.com/vtapi/v2"
    rate_limit: 4  # requests per minute for free tier
  
  shodan:
    api_key: null  # Set via environment variable
    base_url: "https://api.shodan.io"
    rate_limit: 1  # requests per second for free tier
```

## 📖 Usage

### Command Line Interface

#### Check IP Reputation
```bash
# Check single IP
NexusAI --check-ips 8.8.8.8

# Check multiple IPs
NexusAI --check-ips 8.8.8.8 1.1.1.1 208.67.222.222

# JSON output
NexusAI --check-ips 8.8.8.8 --output-format json
```

#### Search Internet Assets
```bash
# Search for Apache servers
NexusAI --search-assets "apache"

# Search for SSH servers
NexusAI --search-assets "ssh"

# Search for specific products
NexusAI --search-assets "product:nginx"
```

#### Enhanced Analysis with Threat Intelligence
```bash
# Run analysis with threat intelligence enabled
NexusAI --input scan.xml --threat-intel
```

### Programmatic Usage

#### Basic IP Reputation Check
```python
from AI_integration.advanced_threat_intel import check_ip_reputation

# Check IP reputation
result = check_ip_reputation("8.8.8.8")
print(f"Threat level: {result['indicators']['8.8.8.8']['threat_level']}")
```

#### Search Internet Assets
```python
from AI_integration.advanced_threat_intel import search_internet_assets

# Search for assets
result = search_internet_assets("apache", limit=10)
print(f"Found {result['total']} assets")
```

#### Advanced Threat Intelligence
```python
from AI_integration.advanced_threat_intel import AdvancedThreatIntel

# Initialize threat intelligence
ati = AdvancedThreatIntel()

# Check multiple indicators
indicators = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
result = ati.aggregate_threat_feeds(indicators)

# Analyze results
for indicator, data in result["indicators"].items():
    print(f"{indicator}: {data['threat_level']} threat")
```

## 📊 Output Format

### Threat Intelligence Results
```json
{
  "summary": {
    "total_indicators": 3,
    "malicious_count": 1,
    "suspicious_count": 1,
    "clean_count": 1
  },
  "indicators": {
    "8.8.8.8": {
      "virustotal": {
        "detection_ratio": "0/70",
        "detection_rate": 0.0,
        "detected_by": []
      },
      "shodan": {
        "ports": [53],
        "vulns": [],
        "org": "Google LLC"
      },
      "reputation_score": 0,
      "threat_level": "clean"
    }
  }
}
```

### Shodan Search Results
```json
{
  "total": 1500000,
  "query": "apache",
  "matches": [
    {
      "ip": "192.168.1.1",
      "port": 80,
      "protocol": "tcp",
      "product": "Apache",
      "version": "2.4.41",
      "org": "Example Corp",
      "location": {
        "city": "New York",
        "country_name": "United States"
      }
    }
  ]
}
```

## 🔍 Analysis Capabilities

### Reputation Scoring Algorithm
The system uses a sophisticated scoring algorithm that considers:

1. **VirusTotal Detection Rate** (60% weight)
   - Percentage of antivirus engines detecting the indicator
   - Recent detection history

2. **Shodan Vulnerability Assessment** (40% weight)
   - Number of open ports
   - Known vulnerabilities
   - Risky port exposure

### Threat Level Classification
- **Clean** (0-19): No significant threats detected
- **Low** (20-39): Minor concerns, monitor closely
- **Medium** (40-69): Moderate risk, investigate further
- **High** (70-100): High risk, immediate attention required

## 🛡️ Security Considerations

### API Key Security
- **Never commit API keys to version control**
- Use environment variables for all API keys
- Rotate API keys regularly
- Monitor API usage and rate limits

### Rate Limiting
- **VirusTotal**: 4 requests/minute (free tier)
- **Shodan**: 1 request/second (free tier)
- Implement proper rate limiting in production

### Data Privacy
- Be cautious with sensitive data
- Review API terms of service
- Implement data retention policies

## 🔧 Advanced Configuration

### Custom Threat Feeds
You can extend the system with additional threat feeds:

```python
class CustomThreatFeed:
    def __init__(self, api_key):
        self.api_key = api_key
    
    def check_indicator(self, indicator):
        # Implement your custom threat feed logic
        pass

# Add to AdvancedThreatIntel class
def add_custom_feed(self, feed_name, feed_instance):
    self.custom_feeds[feed_name] = feed_instance
```

### Rate Limiting Configuration
```python
# Configure rate limiting
ati = AdvancedThreatIntel()
ati.set_rate_limit("virustotal", 4)  # 4 requests per minute
ati.set_rate_limit("shodan", 1)      # 1 request per second
```

## 📈 Performance Optimization

### Caching
The system implements intelligent caching to reduce API calls:

```python
# Enable caching
ati = AdvancedThreatIntel()
ati.enable_caching(ttl=3600)  # Cache for 1 hour
```

### Batch Processing
For multiple indicators, use batch processing:

```python
# Process multiple indicators efficiently
indicators = ["ip1", "ip2", "ip3", "ip4", "ip5"]
result = ati.aggregate_threat_feeds(indicators)
```

## 🚨 Troubleshooting

### Common Issues

#### API Key Errors
```
Error: VirusTotal API key not configured
```
**Solution**: Set the environment variable:
```bash
export VIRUSTOTAL_API_KEY="your_key_here"
```

#### Rate Limit Errors
```
Error: VirusTotal API error: 429
```
**Solution**: Implement proper rate limiting or upgrade API plan

#### Network Errors
```
Error: Shodan request failed: Connection timeout
```
**Solution**: Check network connectivity and API endpoint availability

### Debug Mode
Enable debug mode for detailed logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

ati = AdvancedThreatIntel()
ati.set_debug_mode(True)
```

## 📚 API Reference

### AdvancedThreatIntel Class

#### Methods
- `check_virustotal_file(file_hash)`: Check file reputation
- `check_virustotal_url(url)`: Check URL reputation
- `check_virustotal_ip(ip_address)`: Check IP reputation
- `search_shodan(query, limit)`: Search internet assets
- `get_shodan_host(ip_address)`: Get detailed host information
- `aggregate_threat_feeds(indicators)`: Multi-source analysis

#### Properties
- `vt_api_key`: VirusTotal API key
- `shodan_api_key`: Shodan API key
- `session`: HTTP session for API requests

### Convenience Functions
- `check_ip_reputation(ip_address)`: Quick IP reputation check
- `search_internet_assets(query, limit)`: Quick asset search
- `analyze_file_hash(file_hash)`: Quick file analysis

## 🤝 Contributing

To extend the threat intelligence capabilities:

1. **Add New Threat Feeds**: Implement new feed classes
2. **Improve Scoring**: Enhance the reputation scoring algorithm
3. **Add Visualizations**: Create charts and graphs for results
4. **Enhance Reporting**: Improve output formats and readability

## 📄 License

This module is part of NEXUS-AI and follows the same license terms.

## 🔗 External Links

- [VirusTotal API Documentation](https://developers.virustotal.com/reference)
- [Shodan API Documentation](https://developer.shodan.io/api)
- [NEXUS-AI Project](https://github.com/Dreepsy/Project_Nexus) 