"""
NEXUS-AI Advanced Configuration Management
Handles environment variables, configuration loading, and path resolution with enhanced features

This module handles all the configuration stuff. I spent a lot of time making it
robust and user-friendly. It automatically finds config files, handles environment
variables, and creates sensible defaults. The goal was to make setup as painless
as possible.

TODO: The config validation is a bit strict sometimes, need to make it more flexible
TODO: Need to handle corrupted config files better
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Union
from dotenv import load_dotenv
import json
from datetime import datetime
import structlog

# Load environment variables from .env file if it exists
load_dotenv()

class ConfigManager:
    """Advanced configuration management with validation, caching, and humanized defaults
    
    This class handles all the configuration complexity. I wanted to make it really
    robust - it automatically finds config files, handles environment variables,
    and creates sensible defaults. The validation ensures we don't crash on bad config.
    
    Note: The validation is a bit overzealous sometimes, but better safe than sorry
    TODO: The config validation is a bit strict sometimes, need to make it more flexible
    TODO: Need to handle corrupted config files better
    """
    
    def __init__(self, config_path: Optional[str] = None):
        # Find the config file - this handles multiple possible locations
        self.config_path = config_path or self._find_config_file()
        # Load and process the configuration
        self.config = self._load_config()
        # Set up logging with the loaded config
        self._setup_logging()
        # Validate that the config makes sense
        self._validate_config()
        # Set up any missing defaults
        self._setup_defaults()
        
    def _find_config_file(self) -> str:
        """Find the configuration file in various possible locations with intelligent fallback"""
        possible_paths = [
            "config/config.yaml",
            "config.yaml",
            os.path.join(os.path.dirname(__file__), "..", "..", "..", "config", "config.yaml"),
            os.path.join(os.getcwd(), "config", "config.yaml"),
            os.path.join(os.getcwd(), "config.yaml"),
            os.path.expanduser("~/.nexusai/config.yaml"),
            "/etc/nexusai/config.yaml"
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        # Create default config if none exists
        return self._create_default_config()
    
    def _create_default_config(self) -> str:
        """Create a default configuration file with humanized settings"""
        default_config = {
            "app": {
                "name": "NexusAI",
                "version": "2.0.0",
                "environment": os.getenv("NEXUS_ENV", "development"),
                "debug": os.getenv("NEXUS_DEBUG", "false").lower() == "true"
            },
            "paths": {
                "data": "data",
                "models": "models",
                "logs": "logs",
                "cache": "cache",
                "reports": "reports"
            },
            "ai": {
                "model": {
                    "type": "ensemble",
                    "algorithms": ["random_forest", "neural_network", "gradient_boosting"],
                    "confidence_threshold": 0.8,
                    "learning_rate": 0.01,
                    "max_iterations": 1000
                },
                "learning": {
                    "enabled": True,
                    "batch_size": 100,
                    "update_frequency": 3600,
                    "max_samples": 10000
                }
            },
            "security": {
                "validation": {
                    "strict_mode": True,
                    "max_file_size": "100MB",
                    "allowed_extensions": [".xml", ".txt", ".csv", ".json"]
                },
                "encryption": {
                    "enabled": True,
                    "algorithm": "AES-256"
                }
            },
            "performance": {
                "cache_ttl": 3600,
                "max_memory_usage": "2GB",
                "max_disk_size": "20GB",
                "concurrent_requests": 10
            },
            "monitoring": {
                "health_check_interval": 60,
                "metrics_retention_days": 30,
                "alert_thresholds": {
                    "cpu_percent": 80,
                    "memory_percent": 85,
                    "disk_percent": 90
                }
            },
            "threat_intelligence": {
                "virustotal": {
                    "api_key": None,
                    "enabled": True,
                    "rate_limit": 4
                },
                "shodan": {
                    "api_key": None,
                    "enabled": True,
                    "rate_limit": 1
                },
                "abuseipdb": {
                    "api_key": None,
                    "enabled": True
                },
                "otx": {
                    "api_key": None,
                    "enabled": True
                }
            },
            "web": {
                "host": "0.0.0.0",
                "port": 5000,
                "debug": False,
                "ssl_enabled": False
            }
        }
        
        # Ensure config directory exists
        config_dir = os.path.join(os.getcwd(), "config")
        os.makedirs(config_dir, exist_ok=True)
        
        config_path = os.path.join(config_dir, "config.yaml")
        with open(config_path, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False, indent=2)
        
        print(f"✨ Created default configuration at: {config_path}")
        return config_path
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file with enhanced error handling"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            
            # Override with environment variables
            config = self._override_with_env(config)
            
            return config
        except Exception as e:
            raise ValueError(f"Failed to load configuration from {self.config_path}: {e}")
    
    def _override_with_env(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Override configuration with environment variables using intelligent mapping"""
        env_mappings = {
            'VIRUSTOTAL_API_KEY': 'threat_intelligence.virustotal.api_key',
            'SHODAN_API_KEY': 'threat_intelligence.shodan.api_key',
            'DEEPSEEK_API_KEY': 'ai.deepseek.api_key',
            'ABUSEIPDB_API_KEY': 'threat_intelligence.abuseipdb.api_key',
            'OTX_API_KEY': 'threat_intelligence.otx.api_key',
            'NEXUS_ENV': 'app.environment',
            'NEXUS_DEBUG': 'app.debug',
            'NEXUS_LOG_LEVEL': 'logging.level'
        }
        
        for env_var, config_path in env_mappings.items():
            env_value = os.getenv(env_var)
            if env_value is not None:
                self._set_nested_value(config, config_path.split('.'), env_value)
        
        return config
    
    def _set_nested_value(self, config: Dict[str, Any], keys: list, value: Any):
        """Set a nested value in configuration dictionary"""
        current = config
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        current[keys[-1]] = value
    
    def _cleanup_corrupted_cache(self):
        """Clean up corrupted cache files"""
        cache_dir = self.get('paths.cache', 'cache')
        if os.path.exists(cache_dir):
            for filename in os.listdir(cache_dir):
                if filename.endswith('.cache'):
                    filepath = os.path.join(cache_dir, filename)
                    try:
                        # Try to read the file to check if it's valid
                        with open(filepath, 'rb') as f:
                            content = f.read()
                            if not content:
                                os.remove(filepath)
                                continue
                            
                            # Try to parse as JSON
                            try:
                                json.loads(content.decode())
                            except (json.JSONDecodeError, UnicodeDecodeError):
                                # Corrupted file, remove it
                                os.remove(filepath)
                    except Exception:
                        # File is unreadable, remove it
                        try:
                            os.remove(filepath)
                        except OSError:
                            pass

    def _setup_logging(self):
        """Setup structured logging with humanized output"""
        log_level = os.getenv('NEXUS_LOG_LEVEL', 'ERROR')  # Default to ERROR for minimal output
        
        # Clean up corrupted cache files first
        self._cleanup_corrupted_cache()
        
        # Configure structlog for structured logging
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.processors.JSONRenderer()
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        
        self.logger = structlog.get_logger()
        
        # Also setup standard logging for compatibility
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    def _validate_config(self):
        """Validate configuration and provide helpful error messages"""
        required_sections = ['app', 'paths', 'ai', 'security']
        
        for section in required_sections:
            if section not in self.config:
                self.logger.warning(f"Missing configuration section: {section}")
        
        # Validate paths
        for path_key, path_value in self.config.get('paths', {}).items():
            if not os.path.exists(path_value):
                try:
                    os.makedirs(path_value, exist_ok=True)
                    self.logger.info(f"Created directory: {path_value}")
                except Exception as e:
                    self.logger.error(f"Could not create directory {path_value}: {e}")
    
    def _setup_defaults(self):
        """Setup intelligent defaults for missing configuration values"""
        defaults = {
            'app.name': 'NexusAI',
            'app.version': '2.0.0',
            'ai.model.confidence_threshold': 0.8,
            'ai.learning.enabled': True,
            'security.validation.strict_mode': True,
            'performance.cache_ttl': 3600
        }
        
        for key, value in defaults.items():
            if self.get(key) is None:
                self._set_nested_value(self.config, key.split('.'), value)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value with dot notation support"""
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def get_path(self, key: str) -> str:
        """Get and validate a path from configuration"""
        path = self.get(key)
        if not path:
            raise ValueError(f"Path configuration '{key}' not found")
        
        # Expand user path and make absolute
        path = os.path.expanduser(path)
        if not os.path.isabs(path):
            path = os.path.abspath(path)
        
        return path
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a service with intelligent fallback"""
        # Try direct service key first
        key = self.get(f'threat_intelligence.{service}.api_key')
        if key:
            return key
        
        # Try environment variable
        env_key = f'{service.upper()}_API_KEY'
        return os.getenv(env_key)
    
    def validate_api_keys(self) -> Dict[str, bool]:
        """Validate all configured API keys and provide status"""
        services = ['virustotal', 'shodan', 'abuseipdb', 'otx']
        status = {}
        
        for service in services:
            key = self.get_api_key(service)
            status[service] = bool(key and len(key) > 10)
        
        return status
    
    def export_config(self, filepath: str):
        """Export current configuration to file"""
        try:
            with open(filepath, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False, indent=2)
            self.logger.info(f"Configuration exported to: {filepath}")
        except Exception as e:
            self.logger.error(f"Failed to export configuration: {e}")
    
    def reload(self):
        """Reload configuration from file"""
        self.config = self._load_config()
        self._validate_config()
        self._setup_defaults()
        self.logger.info("Configuration reloaded")

# Global configuration instance
_config_instance = None

def get_config() -> ConfigManager:
    """Get global configuration instance"""
    global _config_instance
    if _config_instance is None:
        _config_instance = ConfigManager()
    return _config_instance

def get_logger():
    """Get structured logger instance"""
    return get_config().logger 