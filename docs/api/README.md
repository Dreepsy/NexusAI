# NEXUS-AI API Documentation

## Overview

NEXUS-AI provides a comprehensive API for AI-powered network security analysis. This document describes the available endpoints, request/response formats, and usage examples.

## Base URL

```
https://api.nexus-ai.com/v1
```

## Authentication

All API requests require authentication using API keys. Include your API key in the request header:

```
Authorization: Bearer YOUR_API_KEY
```

## Endpoints

### 1. Network Scan Analysis

#### POST /analyze/scan

Analyze a network scan file and return AI-powered threat assessment.

**Request Body:**
```json
{
  "scan_file": "base64_encoded_scan_content",
  "file_format": "xml",
  "options": {
    "include_threat_intel": true,
    "include_exploits": false,
    "include_mitre_attack": true
  }
}
```

**Response:**
```json
{
  "prediction": "exploits",
  "confidence": 0.92,
  "threat_level": "high",
  "analysis": {
    "open_ports": [22, 80, 443],
    "services": ["ssh", "http", "https"],
    "vulnerabilities": [
      {
        "cve_id": "CVE-2021-41773",
        "severity": "high",
        "description": "Apache path traversal vulnerability"
      }
    ]
  },
  "threat_intelligence": {
    "malicious_indicators": 3,
    "suspicious_indicators": 1,
    "clean_indicators": 0
  },
  "mitre_attack": {
    "techniques": ["T1190", "T1078"],
    "tactics": ["Initial Access", "Execution"],
    "threat_actors": ["APT29", "Lazarus Group"],
    "risk_score": 8
  }
}
```

### 2. Real-time Learning

#### POST /learning/add

Add analysis results to the real-time learning system.

**Request Body:**
```json
{
  "prediction": "exploits",
  "confidence": 0.85,
  "ground_truth": "malicious",
  "features": {
    "open_ports": [22, 80],
    "services": ["ssh", "http"],
    "threat_indicators": 2
  },
  "metadata": {
    "timestamp": "2024-01-15T10:30:00Z",
    "source": "manual_verification"
  }
}
```

#### GET /learning/stats

Get real-time learning statistics.

**Response:**
```json
{
  "total_samples": 1250,
  "queue_size": 15,
  "last_updated": "2024-01-15T10:30:00Z",
  "performance_metrics": {
    "accuracy": 0.89,
    "precision": 0.87,
    "recall": 0.91,
    "f1_score": 0.89
  },
  "model_info": {
    "version": "1.2.0",
    "last_training": "2024-01-15T09:00:00Z",
    "adaptation_count": 5
  }
}
```

### 3. Threat Intelligence

#### GET /threat-intel/cve/{cve_id}

Get detailed threat intelligence for a specific CVE.

**Response:**
```json
{
  "cve_id": "CVE-2021-41773",
  "description": "Apache HTTP Server path traversal vulnerability",
  "severity": "high",
  "cvss_score": 7.5,
  "exploits": [
    {
      "id": "EDB-12345",
      "title": "Apache 2.4.49 Path Traversal",
      "type": "remote",
      "platform": "linux"
    }
  ],
  "kev_status": true,
  "vendor_advisory": "https://httpd.apache.org/security/vulnerabilities_24.html",
  "mitre_attack": {
    "techniques": ["T1190"],
    "tactics": ["Initial Access"]
  }
}
```

#### POST /threat-intel/search

Search for threat intelligence indicators.

**Request Body:**
```json
{
  "indicators": ["192.168.1.100", "malware.example.com"],
  "sources": ["virustotal", "shodan", "abuseipdb"]
}
```

### 4. Model Management

#### GET /models/status

Get current model status and performance.

**Response:**
```json
{
  "active_model": {
    "version": "1.2.0",
    "type": "ensemble",
    "algorithms": ["random_forest", "neural_network"],
    "performance": {
      "accuracy": 0.89,
      "precision": 0.87,
      "recall": 0.91
    }
  },
  "available_models": [
    {
      "version": "1.1.0",
      "type": "ensemble",
      "performance": {
        "accuracy": 0.85
      }
    }
  ]
}
```

#### POST /models/update

Trigger model update with new training data.

**Request Body:**
```json
{
  "trigger_type": "manual",
  "options": {
    "include_online_data": true,
    "validation_threshold": 0.05
  }
}
```

## Error Handling

All API endpoints return appropriate HTTP status codes:

- `200 OK`: Request successful
- `400 Bad Request`: Invalid request parameters
- `401 Unauthorized`: Invalid or missing API key
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error

Error responses include detailed information:

```json
{
  "error": {
    "code": "INVALID_SCAN_FORMAT",
    "message": "Unsupported scan file format",
    "details": {
      "supported_formats": ["xml", "json"],
      "received_format": "txt"
    }
  }
}
```

## Rate Limiting

API requests are rate-limited to ensure fair usage:

- **Free Tier**: 100 requests/hour
- **Pro Tier**: 1000 requests/hour
- **Enterprise Tier**: 10000 requests/hour

Rate limit headers are included in responses:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1642248000
```

## SDK Examples

### Python SDK

```python
from nexusai import NexusAI

# Initialize client
client = NexusAI(api_key="your_api_key")

# Analyze scan
result = client.analyze_scan(
    scan_file="path/to/scan.xml",
    include_threat_intel=True
)

print(f"Prediction: {result.prediction}")
print(f"Confidence: {result.confidence}")
```

### JavaScript SDK

```javascript
const NexusAI = require('nexusai');

const client = new NexusAI({
  apiKey: 'your_api_key'
});

client.analyzeScan({
  scanFile: 'path/to/scan.xml',
  includeThreatIntel: true
}).then(result => {
  console.log(`Prediction: ${result.prediction}`);
  console.log(`Confidence: ${result.confidence}`);
});
```

## Webhooks

Configure webhooks to receive real-time notifications:

```json
{
  "url": "https://your-server.com/webhooks/nexus",
  "events": ["scan.analyzed", "threat.detected"],
  "secret": "your_webhook_secret"
}
```

## Support

For API support and questions:

- **Documentation**: https://docs.nexus-ai.com
- **Email**: api-support@nexus-ai.com
- **Discord**: https://discord.gg/nexus-ai 