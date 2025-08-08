# NexusAI Development Guide

## Introduction

Welcome to the NexusAI development guide! This document helps developers contribute to NexusAI, understand its architecture, and extend its functionality.

## Development Setup

### Prerequisites

- **Python 3.8+**: Required for all development
- **Git**: Version control
- **Docker**: For containerized development (optional)

### Quick Setup

```bash
# Clone and setup
git clone https://github.com/Dreepsy/Project_Nexus.git
cd Project_Nexus

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install

# Create sample model
python scripts/training/create_sample_model.py
```

### Development Tools

```bash
# Code formatting
black src/ tests/
isort src/ tests/

# Type checking
mypy src/

# Linting
flake8 src/ tests/

# Security scanning
bandit -r src/

# Testing
pytest tests/ --cov=src/ --cov-report=html
```

## Project Architecture

### Core Components

```
src/nexus/
├── ai/                    # AI and ML modules
│   ├── real_time_learning.py      # Multi-algorithm learning
│   ├── advanced_threat_intel.py   # Threat intelligence
│   ├── mitre_attack.py           # MITRE ATT&CK mapping
│   ├── exploit_developer.py      # Exploitation guides
│   └── deepseek_integration.py   # DeepSeek AI integration
├── cli/                   # Command-line interface
├── core/                  # Core functionality
├── security/              # Security components
├── web/                   # Web interface
├── monitoring/            # System monitoring
└── optimization/          # Performance optimization
```

### Data Flow

```
User Input → CLI Parser → Security Validation → AI Analysis → Threat Intelligence → Report Generation
```

## Code Standards

### Python Style Guide

Follow PEP 8 with these guidelines:

```python
# Imports: stdlib, third-party, local
import os
from typing import Dict, List, Optional

import numpy as np
import pandas as pd

from nexus.core.config import get_config
from nexus.ai.real_time_learning import RealTimeLearning

class ThreatAnalyzer:
    """Analyzes threats using AI models."""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the threat analyzer."""
        self.config = config or {}
        self._setup_models()
    
    def analyze_threat(self, data: Dict) -> Dict[str, Any]:
        """Analyze threat data.
        
        Args:
            data: Threat data to analyze
            
        Returns:
            Analysis results
            
        Raises:
            ValidationError: If data is invalid
        """
        if not self._validate_data(data):
            raise ValidationError("Invalid data format")
        
        return self._process_data(data)
    
    def _setup_models(self) -> None:
        """Set up AI models."""
        pass
    
    def _validate_data(self, data: Dict) -> bool:
        """Validate input data."""
        return True
```

### Type Hints

Always use type hints:

```python
from typing import Dict, List, Optional, Tuple

def analyze_network_scan(
    scan_path: str,
    output_format: str = "text",
    include_exploitation_guide: bool = False
) -> str:
    """Analyze network scan file.
    
    Args:
        scan_path: Path to scan file
        output_format: Output format ("text" or "json")
        include_exploitation_guide: Whether to include exploitation guide
        
    Returns:
        Analysis results as string
    """
    pass
```

### Error Handling

Use custom exceptions:

```python
class NexusAIError(Exception):
    """Base exception for NexusAI."""
    pass

class ValidationError(NexusAIError):
    """Raised when input validation fails."""
    pass

def safe_function(data: Dict) -> Dict:
    """Example of proper error handling."""
    try:
        if not data:
            raise ValidationError("Data cannot be empty")
        
        result = process_data(data)
        
        if not result:
            raise ModelError("Processing failed")
        
        return result
        
    except ValidationError as e:
        logger.error(f"Validation error: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise NexusAIError(f"Unexpected error: {e}")
```

## Testing Strategy

### Test Structure

```
tests/
├── unit/                    # Unit tests
│   ├── test_ai/           # AI module tests
│   ├── test_core/         # Core module tests
│   └── test_security/     # Security module tests
├── integration/            # Integration tests
├── performance/            # Performance tests
└── fixtures/              # Test fixtures
```

### Unit Testing Example

```python
import pytest
from unittest.mock import Mock, patch
from nexus.ai.real_time_learning import RealTimeLearning

class TestRealTimeLearning:
    """Test cases for RealTimeLearning class."""
    
    @pytest.fixture
    def learner(self):
        """Create a test learner instance."""
        return RealTimeLearning()
    
    def test_add_sample(self, learner):
        """Test adding training sample."""
        # Arrange
        features = {"port_count": 5}
        prediction = 1
        actual = 1
        
        # Act
        learner.add_sample(features, prediction, actual)
        
        # Assert
        assert len(learner.training_data) == 1
        assert learner.training_data[0]["features"] == features
    
    def test_predict_with_empty_data(self, learner):
        """Test prediction with empty training data."""
        features = {"port_count": 3}
        
        with pytest.raises(ValueError, match="No training data"):
            learner.predict(features)
```

### Integration Testing

```python
import pytest
from nexus.cli.commands import analyze_network_scan

class TestIntegration:
    """Integration tests for CLI commands."""
    
    def test_analyze_network_scan(self, sample_scan_file):
        """Test complete scan analysis workflow."""
        # Act
        result = analyze_network_scan(sample_scan_file)
        
        # Assert
        assert "AI PREDICTION" in result
        assert "THREAT INTELLIGENCE" in result
        assert "MITRE ATT&CK" in result
```

### Test Fixtures

```python
import pytest
import tempfile
import os

@pytest.fixture
def sample_scan_file():
    """Create a sample scan file for testing."""
    scan_content = """<?xml version="1.0"?>
    <nmaprun>
        <host>
            <address addr="192.168.1.1" addrtype="ipv4"/>
            <ports>
                <port protocol="tcp" portid="22">
                    <state state="open"/>
                    <service name="ssh"/>
                </port>
            </ports>
        </host>
    </nmaprun>"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
        f.write(scan_content)
        temp_file = f.name
    
    yield temp_file
    
    # Cleanup
    os.unlink(temp_file)
```

## Contributing Guidelines

### Development Workflow

1. **Fork Repository**: Create your own fork
2. **Create Feature Branch**: `git checkout -b feature/your-feature`
3. **Make Changes**: Implement your feature
4. **Write Tests**: Add tests for your changes
5. **Run Tests**: Ensure all tests pass
6. **Format Code**: Run code formatting tools
7. **Commit Changes**: Use conventional commit messages
8. **Push Changes**: Push to your fork
9. **Create Pull Request**: Submit PR for review

### Commit Message Format

Use conventional commit messages:

```
feat: add new exploitation guide feature
fix: resolve API timeout issue
docs: update user guide with new examples
test: add unit tests for threat intelligence
refactor: improve cache management
style: format code with black
```

### Pull Request Guidelines

1. **Title**: Clear, descriptive title
2. **Description**: Detailed description of changes
3. **Tests**: Ensure all tests pass
4. **Documentation**: Update relevant documentation
5. **Screenshots**: Include screenshots for UI changes

## Architecture Deep Dive

### AI Engine Architecture

```python
class AIEngine:
    """Core AI engine for NexusAI."""
    
    def __init__(self):
        self.learning_system = RealTimeLearning()
        self.threat_intel = AdvancedThreatIntel()
        self.mitre_mapper = MITREAttackMapper()
        self.exploit_developer = ExploitDeveloper()
    
    def analyze_scan(self, scan_data: Dict) -> Dict[str, Any]:
        """Complete scan analysis pipeline."""
        # 1. Preprocess scan data
        processed_data = self._preprocess_scan(scan_data)
        
        # 2. AI prediction
        prediction, confidence = self.learning_system.predict(processed_data)
        
        # 3. Threat intelligence
        threat_data = self.threat_intel.analyze_targets(processed_data)
        
        # 4. MITRE ATT&CK mapping
        mitre_data = self.mitre_mapper.map_findings(processed_data)
        
        # 5. Exploitation guide (if requested)
        exploit_guide = None
        if self.config.get("include_exploitation_guide"):
            exploit_guide = self.exploit_developer.generate_guide(processed_data)
        
        return {
            "prediction": prediction,
            "confidence": confidence,
            "threat_intelligence": threat_data,
            "mitre_attack": mitre_data,
            "exploitation_guide": exploit_guide
        }
```

### Data Pipeline

```python
class DataPipeline:
    """Data processing pipeline."""
    
    def __init__(self):
        self.validators = [
            IPValidator(),
            PortValidator(),
            ServiceValidator()
        ]
        self.transformers = [
            FeatureExtractor(),
            Normalizer(),
            Encoder()
        ]
    
    def process_scan_data(self, raw_data: Dict) -> Dict:
        """Process raw scan data through pipeline."""
        # 1. Validation
        for validator in self.validators:
            raw_data = validator.validate(raw_data)
        
        # 2. Transformation
        for transformer in self.transformers:
            raw_data = transformer.transform(raw_data)
        
        # 3. Feature extraction
        features = self._extract_features(raw_data)
        
        return features
```

## Performance Optimization

### Caching Strategy

```python
from functools import lru_cache
from nexus.optimization.cache_manager import CacheManager

class OptimizedAnalyzer:
    """Performance-optimized analyzer."""
    
    def __init__(self):
        self.cache = CacheManager()
    
    @lru_cache(maxsize=1000)
    def _cached_prediction(self, features_hash: str) -> Tuple[int, float]:
        """Cached prediction with hash-based key."""
        # Implementation here
        pass
    
    def analyze_with_cache(self, scan_data: Dict) -> Dict:
        """Analyze with intelligent caching."""
        # Generate cache key
        features_hash = self._hash_features(scan_data)
        
        # Check cache first
        cached_result = self.cache.get(f"prediction:{features_hash}")
        if cached_result:
            return cached_result
        
        # Perform analysis
        result = self._perform_analysis(scan_data)
        
        # Cache result
        self.cache.set(f"prediction:{features_hash}", result, ttl=3600)
        
        return result
```

### Memory Management

```python
import gc
import psutil
from typing import Generator

class MemoryOptimizedProcessor:
    """Memory-optimized data processor."""
    
    def __init__(self):
        self.memory_threshold = 0.8  # 80% memory usage threshold
    
    def process_large_dataset(self, data: List[Dict]) -> Generator[Dict, None, None]:
        """Process large dataset with memory management."""
        batch_size = self._calculate_batch_size()
        
        for i in range(0, len(data), batch_size):
            batch = data[i:i + batch_size]
            
            # Process batch
            for result in self._process_batch(batch):
                yield result
            
            # Memory cleanup
            if self._memory_usage() > self.memory_threshold:
                gc.collect()
    
    def _calculate_batch_size(self) -> int:
        """Calculate optimal batch size based on available memory."""
        available_memory = psutil.virtual_memory().available
        return min(1000, available_memory // (1024 * 1024 * 10))  # 10MB per item
```

## Security Considerations

### Input Validation

```python
import re
from pathlib import Path

class SecurityValidator:
    """Comprehensive input validation."""
    
    def __init__(self):
        self.allowed_extensions = {'.xml', '.json'}
        self.max_file_size = 10 * 1024 * 1024  # 10MB
    
    def validate_file_upload(self, file) -> bool:
        """Validate uploaded file."""
        # Check file extension
        if not self._has_allowed_extension(file.filename):
            return False
        
        # Check file size
        if file.content_length > self.max_file_size:
            return False
        
        # Check for malicious content
        if self._contains_malicious_content(file):
            return False
        
        return True
    
    def validate_ip_address(self, ip: str) -> bool:
        """Validate IP address format."""
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(ip_pattern, ip))
```

### API Security

```python
from functools import wraps
import time
from flask import request, jsonify

class RateLimiter:
    """Rate limiting for API endpoints."""
    
    def __init__(self):
        self.requests = {}
    
    def limit(self, max_requests: int = 100, window: int = 3600):
        """Rate limiting decorator."""
        def decorator(f):
            @wraps(f)
            def wrapped(*args, **kwargs):
                client_ip = request.remote_addr
                current_time = time.time()
                
                # Clean old requests
                self._cleanup_old_requests(client_ip, current_time, window)
                
                # Check rate limit
                if len(self.requests.get(client_ip, [])) >= max_requests:
                    return jsonify({"error": "Rate limit exceeded"}), 429
                
                # Add current request
                if client_ip not in self.requests:
                    self.requests[client_ip] = []
                self.requests[client_ip].append(current_time)
                
                return f(*args, **kwargs)
            return wrapped
        return decorator

# Usage
@app.route('/api/analyze', methods=['POST'])
@rate_limiter.limit(max_requests=10, window=60)
def analyze_scan():
    """Rate-limited scan analysis endpoint."""
    pass
```

## Deployment

### Docker Deployment

```dockerfile
# Dockerfile
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY config/ ./config/

# Create non-root user
RUN useradd -m -u 1000 nexusai && chown -R nexusai:nexusai /app
USER nexusai

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Run application
CMD ["python", "-m", "nexus.web.app"]
```

### Kubernetes Deployment

```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nexusai
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nexusai
  template:
    metadata:
      labels:
        app: nexusai
    spec:
      containers:
      - name: nexusai
        image: nexusai:latest
        ports:
        - containerPort: 5000
        env:
        - name: VIRUSTOTAL_API_KEY
          valueFrom:
            secretKeyRef:
              name: nexusai-secrets
              key: virustotal-api-key
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
```

## Conclusion

This development guide provides essential information for contributing to NexusAI. Key points:

- **Follow Code Standards**: Use consistent style and documentation
- **Write Tests**: Ensure code quality with comprehensive testing
- **Consider Security**: Always validate inputs and protect sensitive data
- **Optimize Performance**: Use caching and efficient algorithms
- **Document Changes**: Keep documentation updated with code changes

Happy coding! 🚀
