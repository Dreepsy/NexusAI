# NexusAI User Guide

## Introduction

Welcome to NexusAI, your advanced AI-powered network security analysis companion! This guide will walk you through everything you need to know to get started with NexusAI, from basic installation to advanced features.

## What is NexusAI?

NexusAI is a sophisticated security analysis platform that combines artificial intelligence with multi-source threat intelligence to provide comprehensive network security insights. Think of it as having a security expert with AI superpowers at your fingertips.

### Key Features

- **🤖 AI-Powered Analysis**: Machine learning models that learn and improve over time
- **🛡️ Multi-Source Intelligence**: Aggregates data from VirusTotal, Shodan, AbuseIPDB, and more
- **📊 Humanized Output**: Clear, actionable insights instead of technical jargon
- **🔧 Exploitation Guides**: Step-by-step instructions for security testing
- **📈 Real-time Learning**: Continuously improves with each analysis
- **🌐 Web Interface**: Modern web-based dashboard
- **⚡ Performance Optimized**: Fast analysis with intelligent caching

## Getting Started

### Installation

#### Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/Dreepsy/Project_Nexus.git
cd Project_Nexus

# Install globally for current user
./install_nexusai_user.sh

# Reload your shell
source ~/.zshrc  # or source ~/.bashrc

# Test the installation
nexusai --help
```

#### Manual Installation

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e .

# Create sample model for testing
python scripts/training/create_sample_model.py
```

### First Steps

1. **Check Installation**:
   ```bash
   nexusai --help
   ```

2. **Set Up API Keys** (Optional but Recommended):
   ```bash
   # Copy example environment file
   cp env.example .env
   
   # Edit .env with your API keys
   export VIRUSTOTAL_API_KEY="your_virustotal_key"
   export SHODAN_API_KEY="your_shodan_key"
   export DEEPSEEK_API_KEY="your_deepseek_key"
   ```

3. **Run Your First Analysis**:
   ```bash
   # Analyze a sample scan
   nexusai --input sample_scan.xml
   ```

## Basic Usage

### Analyzing Network Scans

The most common use case is analyzing Nmap scan results.

#### Standard Analysis

```bash
# Basic scan analysis
nexusai --input scan.xml

# With JSON output for integration
nexusai --input scan.xml --output-format json
```

**What You'll Get:**
- AI prediction of network behavior
- Threat intelligence summary
- MITRE ATT&CK analysis
- Risk assessment
- AI learning statistics

#### With Exploitation Guide

```bash
# Get detailed exploitation guide
nexusai --input scan.xml --guide
```

**Additional Output:**
- Step-by-step exploitation instructions
- Tool recommendations
- Quick exploit commands
- Difficulty assessment
- Safety warnings

### Example Analysis Output

```
🎯 AI PREDICTION: R2L

🤖 AI-GENERATED ANALYSIS:
──────────────────────────────────────────────────
[Detailed vulnerability analysis]

🔍 THREAT INTELLIGENCE SUMMARY:
──────────────────────────────────────────────────
  📊 Total CVEs Analyzed: 5
  💥 Exploits Available: 3
  🚨 CISA KEV CVEs: 2

🎯 MITRE ATT&CK ANALYSIS:
──────────────────────────────────────────────────
  📈 Risk Score: 7/10
  👥 Threat Actors: APT29, Lazarus Group
  🎭 Attack Techniques: T1190, T1133
```

### Checking IP Reputation

```bash
# Check single IP
nexusai --check-ips 8.8.8.8

# Check multiple IPs
nexusai --check-ips 8.8.8.8 1.1.1.1 192.168.1.1
```

**Output Includes:**
- Reputation scores
- Known threats
- Geographic information
- Recent activity

### Searching Internet Assets

```bash
# Search for specific services
nexusai --search-assets "apache"

# Limit results
nexusai --search-assets "nginx" --limit 5
```

**Results Include:**
- IP addresses
- Service versions
- Geographic location
- Risk assessment

## Advanced Features

### AI Learning Statistics

```bash
# View learning progress
nexusai --learning-stats
```

**Shows:**
- Total learning samples
- Model accuracy
- Learning progress
- Performance metrics

### System Health Check

```bash
# Comprehensive health check
nexusai --health-check
```

**Checks:**
- System resources (CPU, memory, disk)
- AI model status
- API connectivity
- Cache performance
- Overall system health

### Web Interface

Launch the modern web interface:

```bash
# Start web server
python -m nexus.web.app

# Open browser to http://localhost:5000
```

**Web Features:**
- Interactive dashboard
- Real-time updates
- Visual charts and graphs
- File upload interface
- Historical analysis

## Practical Examples

### Example 1: Basic Network Analysis

You have a Nmap scan of your network and want to understand the security posture.

```bash
# Run Nmap scan
nmap -sS -sV -O -p- -oX network_scan.xml 192.168.1.0/24

# Analyze with NexusAI
nexusai --input network_scan.xml
```

**What You'll Learn:**
- Which hosts are most vulnerable
- What services are running
- Potential attack vectors
- Risk assessment

### Example 2: Security Testing with Exploitation Guide

You're doing penetration testing and need detailed exploitation instructions.

```bash
# Scan target
nmap -sS -sV -p- -oX target_scan.xml 10.0.0.5

# Get detailed exploitation guide
nexusai --input target_scan.xml --guide
```

**You'll Get:**
- Step-by-step exploitation methods
- Tool recommendations
- Quick commands
- Difficulty assessment
- Safety warnings

### Example 3: Threat Intelligence Research

You want to investigate suspicious IP addresses.

```bash
# Check multiple suspicious IPs
nexusai --check-ips 185.220.101.45 91.121.14.22 45.95.147.12
```

**Analysis Includes:**
- Reputation scores
- Known malicious activity
- Geographic information
- Associated threats

### Example 4: Asset Discovery

You want to find internet-facing assets for your organization.

```bash
# Search for your organization's assets
nexusai --search-assets "your-company.com"
nexusai --search-assets "your-company-ip-range"
```

**Results Show:**
- Exposed services
- Potential vulnerabilities
- Geographic distribution
- Risk assessment

## Configuration

### Environment Variables

Set up your API keys for full functionality:

```bash
# VirusTotal API (free tier available)
export VIRUSTOTAL_API_KEY="your_virustotal_key"

# Shodan API (free tier available)
export SHODAN_API_KEY="your_shodan_key"

# DeepSeek API (for advanced analysis)
export DEEPSEEK_API_KEY="your_deepseek_key"

# AbuseIPDB API (free tier available)
export ABUSEIPDB_API_KEY="your_abuseipdb_key"

# OTX API (free tier available)
export OTX_API_KEY="your_otx_key"
```

### Configuration File

Create a custom configuration file:

```bash
# Copy example config
cp config/config.yaml ~/.nexusai/config.yaml

# Edit configuration
nano ~/.nexusai/config.yaml
```

**Key Configuration Options:**

```yaml
ai:
  learning:
    enabled: true
    batch_size: 100
  models:
    random_forest: true
    neural_network: true
    gradient_boosting: true

security:
  validation:
    enabled: true
    strict_mode: true

performance:
  cache:
    enabled: true
    ttl: 3600
    max_size: 1000
```

## Output Formats

### Text Output (Default)

Human-readable format with emojis and clear sections.

### JSON Output

Machine-readable format for integration:

```bash
nexusai --input scan.xml --output-format json
```

**JSON Structure:**
```json
{
  "ai_prediction": "r2l",
  "confidence": 0.85,
  "threat_intelligence": {
    "cves_analyzed": 5,
    "exploits_available": 3,
    "risk_score": 7
  },
  "mitre_attack": {
    "techniques": ["T1190", "T1133"],
    "tactics": ["Initial Access", "Persistence"]
  }
}
```

## Troubleshooting

### Common Issues

#### Installation Problems

```bash
# Clear cache and reinstall
python cleanup_cache.py
pip install -e . --force-reinstall

# Check Python version
python --version  # Should be 3.8+
```

#### API Key Issues

```bash
# Verify API keys
nexusai --check-api-keys

# Test individual APIs
nexusai --check-ips 8.8.8.8  # Tests VirusTotal and AbuseIPDB
```

#### Model Loading Issues

```bash
# Recreate sample model
python scripts/training/create_sample_model.py

# Check model status
nexusai --model-status
```

#### Performance Issues

```bash
# Clear cache
nexusai --cache-clear

# Check system resources
nexusai --health-check
```

### Getting Help

```bash
# General help
nexusai --help

# Command-specific help
nexusai --input --help

# Verbose output for debugging
nexusai --input scan.xml --verbose
```

## Best Practices

### Security Testing

1. **Always Get Permission**: Only test systems you own or have explicit permission
2. **Use Safe Environments**: Test in isolated environments
3. **Follow Responsible Disclosure**: Report vulnerabilities properly
4. **Document Everything**: Keep detailed records of your testing

### Performance Optimization

1. **Use Caching**: NexusAI automatically caches results
2. **Batch Operations**: Group related scans together
3. **Monitor Resources**: Use health checks regularly
4. **Update Regularly**: Keep NexusAI updated

### Data Management

1. **Backup Configurations**: Save your configuration files
2. **Export Learning Data**: Regularly export AI learning data
3. **Clean Old Data**: Clear cache periodically
4. **Secure API Keys**: Use environment variables for API keys

## Integration Examples

### Scripting with NexusAI

```bash
#!/bin/bash
# Automated security analysis script

# Scan network
nmap -sS -sV -oX scan.xml 192.168.1.0/24

# Analyze with NexusAI
result=$(nexusai --input scan.xml --output-format json)

# Parse results
echo $result | jq '.ai_prediction'
echo $result | jq '.threat_intelligence.risk_score'
```

### Python Integration

```python
import subprocess
import json

def analyze_network_scan(scan_file):
    """Analyze network scan with NexusAI"""
    try:
        result = subprocess.run(
            ['nexusai', '--input', scan_file, '--output-format', 'json'],
            capture_output=True, text=True
        )
        return json.loads(result.stdout)
    except Exception as e:
        print(f"Error: {e}")
        return None

# Usage
scan_result = analyze_network_scan('network_scan.xml')
if scan_result:
    print(f"AI Prediction: {scan_result['ai_prediction']}")
    print(f"Risk Score: {scan_result['threat_intelligence']['risk_score']}")
```

### CI/CD Integration

```yaml
# GitHub Actions example
name: Security Analysis
on: [push, pull_request]

jobs:
  security-analysis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install NexusAI
        run: |
          pip install -e .
          python scripts/training/create_sample_model.py
      - name: Run Security Analysis
        run: |
          nexusai --input scan.xml --output-format json > results.json
      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: security-analysis-results
          path: results.json
```

## Advanced Usage

### Custom Models

Train custom AI models for your specific environment:

```bash
# Train enhanced model
python scripts/training/train_enhanced_ai.py

# Use custom model
nexusai --input scan.xml --model-path models/custom_model.pkl
```

### Batch Processing

Process multiple scans efficiently:

```bash
# Process all XML files in directory
for file in scans/*.xml; do
    nexusai --input "$file" --output-format json > "results/$(basename "$file" .xml).json"
done
```

### Automated Monitoring

Set up continuous monitoring:

```bash
# Create monitoring script
cat > monitor.sh << 'EOF'
#!/bin/bash
while true; do
    # Run health check
    nexusai --health-check > health.log
    
    # Check for issues
    if grep -q "ERROR" health.log; then
        echo "Issues detected: $(date)" >> alerts.log
    fi
    
    sleep 3600  # Check every hour
done
EOF

chmod +x monitor.sh
./monitor.sh &
```

## Tips and Tricks

### Quick Commands

```bash
# Quick IP check
alias quickcheck='nexusai --check-ips'

# Quick scan analysis
alias quickanalyze='nexusai --input'

# Health check shortcut
alias health='nexusai --health-check'
```

### Useful Aliases

Add to your shell configuration:

```bash
# Add to ~/.zshrc or ~/.bashrc
alias nexus='nexusai'
alias nexus-guide='nexusai --guide'
alias nexus-health='nexusai --health-check'
alias nexus-stats='nexusai --learning-stats'
```

### Keyboard Shortcuts

In the web interface:
- `Ctrl+U`: Upload scan file
- `Ctrl+H`: View history
- `Ctrl+S`: Save results
- `Ctrl+R`: Refresh dashboard

## Conclusion

NexusAI is designed to be your intelligent security companion, providing sophisticated analysis with humanized insights. Whether you're a security professional, penetration tester, or network administrator, NexusAI can help you understand and secure your networks more effectively.

Remember:
- **Start Simple**: Begin with basic scan analysis
- **Learn Gradually**: Explore advanced features as you become comfortable
- **Stay Updated**: Keep NexusAI and your API keys current
- **Practice Safely**: Always test in controlled environments
- **Share Knowledge**: Contribute to the community

Happy analyzing! 🚀
