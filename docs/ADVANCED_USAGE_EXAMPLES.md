# NexusAI Advanced Usage Examples

## Overview

This document provides detailed examples for advanced NexusAI features, including exploit generation, threat intelligence, real-time learning, and custom configurations.

*I created these examples to help users understand the more advanced features of NexusAI. Some of the examples are pretty complex, but they show what the system is capable of. I tried to include realistic use cases that you might actually encounter.*

*Note: These examples assume you have the basic setup working. If you're having trouble with the basics, check the main README first.*

## Table of Contents

1. [Exploit Generation Examples](#exploit-generation-examples)
2. [Threat Intelligence Integration](#threat-intelligence-integration)
3. [Real-time Learning Configuration](#real-time-learning-configuration)
4. [Custom Exploit Development](#custom-exploit-development)
5. [Advanced Configuration](#advanced-configuration)
6. [API Integration Examples](#api-integration-examples)
7. [Performance Optimization](#performance-optimization)

## Exploit Generation Examples

### 1. Basic SSH Exploit Generation

```python
from nexus.ai.exploit_developer import ExploitDeveloper
from nexus.ai.exploit_generators import ExploitGenerators

# Initialize exploit developer
exploit_dev = ExploitDeveloper()

# Define vulnerability
vulnerability = {
    'service': 'ssh',
    'host': '192.168.1.100',
    'port': 22,
    'version': 'OpenSSH 7.9',
    'risk_level': 'high'
}

# Generate SSH exploit
exploit_code = exploit_dev._generate_ssh_exploit(
    vulnerability['host'], 
    vulnerability['port'], 
    vulnerability
)

# Save exploit to file
with open('ssh_exploit.py', 'w') as f:
    f.write(exploit_code)

print("SSH exploit generated successfully!")
```

### 2. HTTP Vulnerability Testing

```python
from nexus.ai.exploit_generators import ExploitGenerators

generators = ExploitGenerators()

# Generate HTTP exploit with comprehensive testing
http_exploit = generators.generate_http_exploit(
    host="192.168.1.100",
    port="80",
    vuln={
        'service': 'http',
        'risk_level': 'medium',
        'vulnerabilities': ['sql_injection', 'xss', 'directory_traversal']
    }
)

# The generated exploit includes:
# - SQL injection testing
# - XSS vulnerability detection
# - Directory traversal testing
# - Endpoint discovery
# - Security header analysis
```

### 3. Database Exploit Generation

```python
# MySQL exploit generation
mysql_exploit = generators.generate_mysql_exploit(
    host="192.168.1.100",
    port="3306",
    vuln={
        'service': 'mysql',
        'version': 'MySQL 5.7',
        'risk_level': 'high'
    }
)

# Redis exploit generation
redis_exploit = generators.generate_redis_exploit(
    host="192.168.1.100",
    port="6379",
    vuln={
        'service': 'redis',
        'version': 'Redis 6.0',
        'risk_level': 'medium'
    }
)
```

## Threat Intelligence Integration

### 1. Multi-Source IP Reputation Check

```python
from nexus.ai.advanced_threat_intel import AdvancedThreatIntel

# Initialize threat intelligence
threat_intel = AdvancedThreatIntel()

# Check multiple IPs
ips_to_check = ['8.8.8.8', '1.1.1.1', '192.168.1.100']

# Get comprehensive threat intelligence
results = threat_intel.aggregate_threat_feeds(ips_to_check)

# Process results
for ip, data in results['indicators'].items():
    print(f"IP: {ip}")
    print(f"  Threat Level: {data['threat_level']}")
    print(f"  Reputation Score: {data['reputation_score']}/100")
    print(f"  Sources: {', '.join(data['sources'])}")
    print(f"  Recommendations: {data['recommendations']}")
    print()
```

### 2. Asset Discovery with Shodan

```python
# Search for internet assets
search_query = "apache server"
results = threat_intel.search_internet_assets(search_query)

print(f"Found {results['total']} assets matching '{search_query}'")

for asset in results['matches'][:5]:
    print(f"IP: {asset['ip']}")
    print(f"  Ports: {asset['ports']}")
    print(f"  Services: {asset['services']}")
    print(f"  Location: {asset['location']}")
    print()
```

### 3. Custom Threat Intelligence Workflow

```python
import asyncio
from typing import List, Dict

async def custom_threat_analysis(ips: List[str]) -> Dict:
    """Custom threat analysis workflow"""
    
    threat_intel = AdvancedThreatIntel()
    results = {}
    
    for ip in ips:
        # Get basic threat data
        threat_data = threat_intel._analyze_single_ip(ip)
        
        # Custom analysis logic
        risk_score = 0
        if threat_data.get('virustotal', {}).get('detection_ratio', 0) > 0.1:
            risk_score += 30
        
        if threat_data.get('abuseipdb', {}).get('abuse_confidence', 0) > 50:
            risk_score += 40
            
        if threat_data.get('shodan', {}).get('ports', []):
            risk_score += 20
            
        # Categorize risk
        if risk_score > 70:
            risk_level = 'critical'
        elif risk_score > 50:
            risk_level = 'high'
        elif risk_score > 30:
            risk_level = 'medium'
        else:
            risk_level = 'low'
            
        results[ip] = {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'threat_data': threat_data,
            'recommendations': [
                'Block IP if risk_score > 70',
                'Monitor traffic if risk_score > 50',
                'Log access for analysis'
            ]
        }
    
    return results

# Usage
ips = ['192.168.1.100', '10.0.0.1', '172.16.0.1']
results = asyncio.run(custom_threat_analysis(ips))
```

## Real-time Learning Configuration

### 1. Custom Learning Configuration

```python
from nexus.ai.real_time_learning import RealTimeLearning

# Custom learning configuration
learning_config = {
    'ai': {
        'learning': {
            'enabled': True,
            'batch_size': 50,  # Smaller batches for faster learning
            'update_frequency': 1800,  # Update every 30 minutes
            'max_samples': 5000,  # Limit dataset size
            'learning_rate': 0.005,  # Slower learning rate
            'performance_threshold': 0.85  # Higher accuracy requirement
        }
    }
}

# Initialize learning system with custom config
learning_system = RealTimeLearning(learning_config)

# Add custom learning samples
sample = {
    'features': {
        'service': 'ssh',
        'port': 22,
        'version': 'OpenSSH 7.9',
        'risk_indicators': ['default_credentials', 'weak_crypto']
    },
    'prediction': {
        'risk_level': 'high',
        'confidence': 0.92
    },
    'ground_truth': 'high',
    'metadata': {
        'source': 'manual_analysis',
        'analyst': 'security_team'
    }
}

learning_system.add_sample(sample)
```

### 2. Learning Performance Monitoring

```python
# Get learning statistics
stats = learning_system.get_statistics()

print("Learning System Statistics:")
print(f"  Total Samples: {stats['total_samples']}")
print(f"  Current Accuracy: {stats['current_accuracy']:.2%}")
print(f"  Learning Rate: {stats['learning_rate']}")
print(f"  Performance Score: {stats['performance_score']:.2f}")

# Get learning insights
insights = learning_system._generate_learning_insights()
print("\nLearning Insights:")
for insight in insights:
    print(f"  - {insight}")

# Get recommendations
recommendations = learning_system._generate_learning_recommendations()
print("\nRecommendations:")
for rec in recommendations:
    print(f"  - {rec}")
```

### 3. Model Versioning and Rollback

```python
# Save model checkpoint
learning_system._save_model_checkpoint()

# Check if model should be updated
if learning_system._should_update_model():
    print("Model update triggered")
    learning_system._trigger_model_update()
else:
    print("Model performing well, no update needed")

# Export learning data for backup
import json
with open('learning_backup.json', 'w') as f:
    json.dump(learning_system.dataset, f, indent=2, default=str)
```

## Custom Exploit Development

### 1. Creating Custom Exploit Templates

```python
from nexus.ai.exploit_config import ExploitConfig

# Define custom exploit template
custom_template = '''
#!/usr/bin/env python3
"""
Custom {service} Exploit for {host}:{port}
Generated by NexusAI - Educational purposes only
"""

import requests
import socket
import sys
from typing import Optional

class Custom{service_upper}Exploit:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.base_url = f"http://{{host}}:{{port}}"
    
    def test_connection(self) -> bool:
        """Test connection to the service"""
        try:
            response = requests.get(self.base_url, timeout=10)
            return response.status_code == 200
        except Exception:
            return False
    
    def custom_vulnerability_test(self) -> dict:
        """Custom vulnerability testing logic"""
        results = {{
            'vulnerable': False,
            'details': [],
            'recommendations': []
        }}
        
        # Add your custom testing logic here
        # Example: Test for specific vulnerabilities
        
        return results

def main():
    """Main exploit function"""
    host = "{host}"
    port = {port}
    
    print(f"[*] Starting custom {service} exploit against {{host}}:{{port}}")
    
    exploit = Custom{service_upper}Exploit(host, port)
    
    if exploit.test_connection():
        print("[+] Service is accessible")
        
        # Run custom tests
        results = exploit.custom_vulnerability_test()
        if results['vulnerable']:
            print("[+] Vulnerabilities found!")
            for detail in results['details']:
                print(f"    - {{detail}}")
        else:
            print("[-] No vulnerabilities detected")
    else:
        print("[-] Service is not accessible")

if __name__ == "__main__":
    main()
'''

# Register custom template
ExploitConfig.PAYLOAD_TEMPLATES['custom_template'] = custom_template
```

### 2. Custom Evasion Techniques

```python
def custom_obfuscation_technique(code: str) -> str:
    """Custom code obfuscation technique"""
    
    # Replace common patterns
    replacements = {
        'requests.get': 'r.get',
        'requests.post': 'r.post',
        'print(': 'p(',
        'socket.socket': 's.socket'
    }
    
    for old, new in replacements.items():
        code = code.replace(old, new)
    
    # Add junk code
    junk_code = '''
import random
import time
import os

def _junk_function():
    return random.randint(1, 100)

def _delay_execution():
    time.sleep(random.uniform(0.1, 0.5))
'''
    
    # Insert junk code at the beginning
    code = junk_code + '\n' + code
    
    return code

# Apply custom obfuscation
original_code = '''
import requests
print("Testing connection")
response = requests.get("http://example.com")
'''

obfuscated_code = custom_obfuscation_technique(original_code)
print("Obfuscated code:")
print(obfuscated_code)
```

### 3. Custom Exploit Validation

```python
def validate_exploit_safety(exploit_code: str) -> dict:
    """Custom exploit safety validation"""
    
    safety_checks = {
        'dangerous_imports': ['subprocess', 'os.system', 'eval', 'exec'],
        'dangerous_functions': ['system(', 'popen(', 'shell=True'],
        'network_restrictions': ['localhost', '127.0.0.1', '0.0.0.0'],
        'required_warnings': ['educational', 'test', 'authorized']
    }
    
    results = {
        'safe': True,
        'warnings': [],
        'errors': []
    }
    
    # Check for dangerous imports
    for dangerous_import in safety_checks['dangerous_imports']:
        if f'import {dangerous_import}' in exploit_code:
            results['warnings'].append(f'Dangerous import: {dangerous_import}')
    
    # Check for dangerous functions
    for dangerous_func in safety_checks['dangerous_functions']:
        if dangerous_func in exploit_code:
            results['errors'].append(f'Dangerous function: {dangerous_func}')
            results['safe'] = False
    
    # Check for required warnings
    has_warning = False
    for warning in safety_checks['required_warnings']:
        if warning.lower() in exploit_code.lower():
            has_warning = True
            break
    
    if not has_warning:
        results['warnings'].append('Missing educational purpose warning')
    
    return results

# Usage
exploit_code = '''
#!/usr/bin/env python3
# Educational purposes only
import requests

def test_connection():
    response = requests.get("http://example.com")
    return response.status_code == 200
'''

safety_results = validate_exploit_safety(exploit_code)
print("Safety validation results:")
print(f"  Safe: {safety_results['safe']}")
print(f"  Warnings: {safety_results['warnings']}")
print(f"  Errors: {safety_results['errors']}")
```

## Advanced Configuration

### 1. Custom Configuration Management

```python
from nexus.core.config import ConfigManager
import yaml

# Create custom configuration
custom_config = {
    'exploit': {
        'custom_templates': {
            'enabled': True,
            'template_dir': 'custom_templates/',
            'auto_load': True
        },
        'safety': {
            'strict_mode': True,
            'require_warnings': True,
            'block_dangerous_imports': True
        },
        'performance': {
            'max_concurrent_exploits': 5,
            'timeout_per_exploit': 300,
            'memory_limit': '1GB'
        }
    },
    'threat_intelligence': {
        'custom_sources': {
            'enabled': True,
            'sources': [
                {
                    'name': 'custom_api',
                    'url': 'https://api.custom.com/threats',
                    'api_key_env': 'CUSTOM_API_KEY',
                    'rate_limit': 10
                }
            ]
        }
    }
}

# Save custom configuration
with open('custom_config.yaml', 'w') as f:
    yaml.dump(custom_config, f, default_flow_style=False)

# Load custom configuration
config_manager = ConfigManager('custom_config.yaml')
```

### 2. Environment-Specific Configuration

```python
import os

# Development configuration
dev_config = {
    'app': {
        'environment': 'development',
        'debug': True,
        'log_level': 'DEBUG'
    },
    'ai': {
        'learning': {
            'enabled': True,
            'batch_size': 10,  # Smaller batches for development
            'update_frequency': 300  # More frequent updates
        }
    },
    'security': {
        'validation': {
            'strict_mode': False,  # Less strict in development
            'max_file_size': '10MB'
        }
    }
}

# Production configuration
prod_config = {
    'app': {
        'environment': 'production',
        'debug': False,
        'log_level': 'INFO'
    },
    'ai': {
        'learning': {
            'enabled': True,
            'batch_size': 100,
            'update_frequency': 3600
        }
    },
    'security': {
        'validation': {
            'strict_mode': True,
            'max_file_size': '100MB'
        }
    }
}

# Load configuration based on environment
env = os.getenv('NEXUS_ENV', 'development')
if env == 'production':
    config = prod_config
else:
    config = dev_config

# Save environment-specific config
config_file = f'config_{env}.yaml'
with open(config_file, 'w') as f:
    yaml.dump(config, f, default_flow_style=False)
```

## API Integration Examples

### 1. REST API Integration

```python
import requests
import json

class NexusAIClient:
    def __init__(self, base_url: str, api_key: str = None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        if api_key:
            self.session.headers['Authorization'] = f'Bearer {api_key}'
    
    def analyze_scan(self, scan_file_path: str) -> dict:
        """Analyze network scan file"""
        
        with open(scan_file_path, 'rb') as f:
            files = {'file': f}
            response = self.session.post(
                f'{self.base_url}/api/analyze',
                files=files
            )
        
        return response.json()
    
    def check_threat_intelligence(self, ips: list) -> dict:
        """Check threat intelligence for IPs"""
        
        data = {'ips': ips}
        response = self.session.post(
            f'{self.base_url}/api/threat-intel/check-ips',
            json=data
        )
        
        return response.json()
    
    def get_learning_stats(self) -> dict:
        """Get learning system statistics"""
        
        response = self.session.get(f'{self.base_url}/api/learning/stats')
        return response.json()
    
    def generate_exploit(self, vulnerability: dict) -> dict:
        """Generate exploit for vulnerability"""
        
        response = self.session.post(
            f'{self.base_url}/api/exploit/generate',
            json=vulnerability
        )
        
        return response.json()

# Usage
client = NexusAIClient('http://localhost:5000', api_key='your_api_key')

# Analyze scan
results = client.analyze_scan('network_scan.xml')
print(f"Analysis completed: {results['status']}")

# Check threat intelligence
threat_results = client.check_threat_intelligence(['8.8.8.8', '1.1.1.1'])
print(f"Threat check completed: {len(threat_results['indicators'])} IPs analyzed")

# Get learning stats
stats = client.get_learning_stats()
print(f"Learning system: {stats['total_samples']} samples processed")
```

### 2. WebSocket Integration

```python
import socketio
import asyncio

class NexusAIWebSocketClient:
    def __init__(self, server_url: str):
        self.sio = socketio.AsyncClient()
        self.server_url = server_url
        self.setup_handlers()
    
    def setup_handlers(self):
        """Setup WebSocket event handlers"""
        
        @self.sio.event
        async def connect():
            print("Connected to NexusAI WebSocket server")
        
        @self.sio.event
        async def disconnect():
            print("Disconnected from NexusAI WebSocket server")
        
        @self.sio.event
        async def analysis_progress(data):
            print(f"Analysis progress: {data['progress']}% - {data['message']}")
        
        @self.sio.event
        async def exploit_generated(data):
            print(f"Exploit generated: {data['name']} for {data['service']}")
        
        @self.sio.event
        async def threat_alert(data):
            print(f"Threat alert: {data['level']} - {data['description']}")
    
    async def connect_to_server(self):
        """Connect to WebSocket server"""
        await self.sio.connect(self.server_url)
    
    async def request_health_update(self):
        """Request health status update"""
        await self.sio.emit('request_health_update')
    
    async def subscribe_to_alerts(self, alert_types: list):
        """Subscribe to specific alert types"""
        await self.sio.emit('subscribe_alerts', {'types': alert_types})
    
    async def disconnect_from_server(self):
        """Disconnect from WebSocket server"""
        await self.sio.disconnect()

# Usage
async def main():
    client = NexusAIWebSocketClient('http://localhost:5000')
    
    await client.connect_to_server()
    
    # Subscribe to alerts
    await client.subscribe_to_alerts(['threat', 'exploit', 'analysis'])
    
    # Request health update
    await client.request_health_update()
    
    # Keep connection alive
    await asyncio.sleep(60)
    
    await client.disconnect_from_server()

# Run WebSocket client
asyncio.run(main())
```

## Performance Optimization

### 1. Caching Strategy

```python
from nexus.optimization.cache_manager import CacheManager

# Initialize cache manager with custom settings
cache_manager = CacheManager(cache_dir='custom_cache')

# Cache expensive operations
@cache_manager.cached(ttl=3600, namespace='threat_intel')
def expensive_threat_lookup(ip: str) -> dict:
    """Expensive threat intelligence lookup"""
    # Simulate expensive API call
    import time
    time.sleep(2)
    return {'ip': ip, 'threat_level': 'medium', 'score': 75}

# Cache exploit generation
@cache_manager.cached(ttl=1800, namespace='exploits')
def generate_exploit_for_service(service: str, version: str) -> str:
    """Generate exploit for service and version"""
    # Simulate exploit generation
    return f"# Exploit for {service} {version}\nprint('test')"

# Usage
results = []
for ip in ['8.8.8.8', '1.1.1.1', '192.168.1.1']:
    result = expensive_threat_lookup(ip)
    results.append(result)

# Check cache statistics
stats = cache_manager.get_stats()
print(f"Cache hit rate: {stats['hits'] / (stats['hits'] + stats['misses']):.2%}")
```

### 2. Batch Processing

```python
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict

async def batch_threat_analysis(ips: List[str], batch_size: int = 10) -> Dict:
    """Batch process threat intelligence analysis"""
    
    threat_intel = AdvancedThreatIntel()
    results = {}
    
    # Process in batches
    for i in range(0, len(ips), batch_size):
        batch = ips[i:i + batch_size]
        
        # Process batch concurrently
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [
                executor.submit(threat_intel._analyze_single_ip, ip)
                for ip in batch
            ]
            
            # Collect results
            for ip, future in zip(batch, futures):
                try:
                    results[ip] = future.result()
                except Exception as e:
                    results[ip] = {'error': str(e)}
        
        # Add delay between batches to respect rate limits
        await asyncio.sleep(1)
    
    return results

# Usage
ips = [f'192.168.1.{i}' for i in range(1, 101)]  # 100 IPs
results = asyncio.run(batch_threat_analysis(ips, batch_size=10))

print(f"Processed {len(results)} IPs")
print(f"Successful: {len([r for r in results.values() if 'error' not in r])}")
print(f"Errors: {len([r for r in results.values() if 'error' in r])}")
```

### 3. Memory Optimization

```python
import gc
import psutil
import threading
from typing import Generator

class MemoryOptimizedProcessor:
    def __init__(self, max_memory_mb: int = 512):
        self.max_memory_mb = max_memory_mb
        self.processed_count = 0
    
    def process_large_dataset(self, data_generator: Generator) -> Generator:
        """Process large dataset with memory management"""
        
        for item in data_generator:
            # Process item
            processed_item = self.process_item(item)
            yield processed_item
            
            self.processed_count += 1
            
            # Check memory usage
            memory_usage = psutil.Process().memory_info().rss / 1024 / 1024
            
            if memory_usage > self.max_memory_mb:
                # Force garbage collection
                gc.collect()
                
                # Log memory usage
                print(f"Memory usage: {memory_usage:.1f}MB, processed: {self.processed_count}")
    
    def process_item(self, item: dict) -> dict:
        """Process individual item"""
        # Add processing logic here
        return {
            'processed': True,
            'original': item,
            'timestamp': time.time()
        }

# Usage
def generate_large_dataset():
    """Generate large dataset for testing"""
    for i in range(10000):
        yield {
            'id': i,
            'data': f'item_{i}',
            'metadata': {'size': len(f'item_{i}')}
        }

# Process with memory optimization
processor = MemoryOptimizedProcessor(max_memory_mb=256)

for processed_item in processor.process_large_dataset(generate_large_dataset()):
    # Handle processed item
    if processed_item['id'] % 1000 == 0:
        print(f"Processed {processed_item['id']} items")
```

## Conclusion

These advanced usage examples demonstrate the flexibility and power of NexusAI. The system is designed to be:

1. **Extensible**: Easy to add custom functionality
2. **Configurable**: Highly customizable for different use cases
3. **Performant**: Optimized for large-scale operations
4. **Secure**: Built-in safety measures and validation
5. **Educational**: Focus on learning and understanding

Remember to always use these tools responsibly and only on systems you own or have explicit permission to test.
