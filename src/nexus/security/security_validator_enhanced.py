"""
Enhanced Security Validator for NEXUS-AI
Provides comprehensive input validation, sanitization, and audit logging

TODO: The regex patterns could be more comprehensive
TODO: Need to handle edge cases in file validation better
TODO: The audit logging can get pretty verbose sometimes
TODO: The file size validation is a bit strict sometimes
TODO: Should probably add more file type detection
"""

import re
import ipaddress
import hashlib
import os
import sys
import json
from typing import Dict, List, Optional, Any, Union
from urllib.parse import urlparse
import yaml
from datetime import datetime
from pathlib import Path
import structlog
from cryptography.fernet import Fernet
from ..core.config import get_config, get_logger

class EnhancedSecurityValidator:
    """Enhanced security validation with comprehensive checks and audit logging"""
    
    def __init__(self):
        try:
            self.config = get_config()
        except Exception as e:
            # Fallback configuration if main config fails
            # This happens sometimes when the config file is corrupted
            # TODO: Should probably add better config validation
            self.config = {
                'security': {
                    'max_file_size': 50 * 1024 * 1024,
                    'allowed_extensions': ['.xml', '.txt', '.csv', '.json', '.yaml', '.yml'],
                    'encryption_enabled': True
                }
            }
        
        self.logger = get_logger()
        self.audit_log = []
        
        # Initialize encryption for sensitive data
        self._setup_encryption()
        
        # Security patterns
        self.dangerous_patterns = {
            'sql_injection': [
                r'(\b(union|select|insert|update|delete|drop|create|alter)\b)',
                r'(\b(or|and)\s+\d+\s*=\s*\d+)',
                r'(\b(union|select|insert|update|delete|drop|create|alter)\b)',
            ],
            'xss': [
                r'<script[^>]*>.*?</script>',
                r'javascript:',
                r'vbscript:',
                r'onload\s*=',
                r'onerror\s*=',
                r'<iframe[^>]*>',
                r'<object[^>]*>',
                r'<embed[^>]*>',
            ],
            'path_traversal': [
                r'\.\./',
                r'\.\.\\',
                r'%2e%2e%2f',
                r'%2e%2e%5c',
                r'\.\.%2f',
                r'\.\.%5c',
            ],
            'command_injection': [
                r'[;&|`$(){}]',
                r'\b(cat|ls|pwd|whoami|id|uname|ps|netstat)\b',
                r'\b(rm|del|format|fdisk|mkfs)\b',
            ],
            'xxe': [
                r'<!DOCTYPE[^>]*SYSTEM',
                r'<!ENTITY[^>]*SYSTEM',
                r'<!ENTITY[^>]*PUBLIC',
                r'<!ELEMENT[^>]*SYSTEM',
            ]
        }
        
        # Allowed file extensions and MIME types
        self.allowed_extensions = {
            '.xml': 'application/xml',
            '.txt': 'text/plain',
            '.csv': 'text/csv',
            '.json': 'application/json',
            '.yaml': 'application/x-yaml',
            '.yml': 'application/x-yaml'
        }
        
        # Maximum file sizes (in bytes)
        self.max_file_sizes = {
            '.xml': 50 * 1024 * 1024,  # 50MB
            '.txt': 100 * 1024 * 1024,  # 100MB
            '.csv': 200 * 1024 * 1024,  # 200MB
            '.json': 10 * 1024 * 1024,  # 10MB
            '.yaml': 1 * 1024 * 1024,   # 1MB
            '.yml': 1 * 1024 * 1024     # 1MB
        }
    
    def _setup_encryption(self):
        """Setup encryption for sensitive data"""
        try:
            # Try to get encryption key from environment
            key = os.getenv('NEXUS_ENCRYPTION_KEY')
            if not key:
                # Generate a new key if none exists
                key = Fernet.generate_key()
                self.logger.warning("No encryption key found, generated new key")
            
            self.cipher = Fernet(key)
        except Exception as e:
            self.logger.error("Failed to setup encryption", error=str(e))
            self.cipher = None
    
    def _audit_log(self, action: str, details: Dict[str, Any], risk_level: str = "low"):
        """Log security audit events"""
        audit_entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'details': details,
            'risk_level': risk_level,
            'user_agent': os.getenv('HTTP_USER_AGENT', 'unknown'),
            'ip_address': os.getenv('REMOTE_ADDR', 'unknown')
        }
        
        self.audit_log.append(audit_entry)
        self.logger.info("Security audit", **audit_entry)
    
    def validate_and_sanitize_input(self, input_data: Union[str, bytes], 
                                   input_type: str = "text") -> Dict[str, Any]:
        """Comprehensive input validation and sanitization"""
        result = {
            'valid': False,
            'sanitized': None,
            'warnings': [],
            'errors': [],
            'risk_score': 0
        }
        
        try:
            # Convert bytes to string if needed
            if isinstance(input_data, bytes):
                input_data = input_data.decode('utf-8', errors='ignore')
            
            # Basic validation
            if not input_data or not input_data.strip():
                result['errors'].append("Input is empty or whitespace only")
                return result
            
            # Check for dangerous patterns
            risk_score = 0
            for pattern_type, patterns in self.dangerous_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, input_data, re.IGNORECASE):
                        result['warnings'].append(f"Potential {pattern_type} detected")
                        risk_score += 10
            
            # Sanitize input based on type
            sanitized = self._sanitize_by_type(input_data, input_type)
            
            # Additional type-specific validation
            if input_type == "url":
                url_validation = self.validate_url(input_data)
                result['warnings'].extend(url_validation.get('warnings', []))
                result['errors'].extend(url_validation.get('errors', []))
                risk_score += url_validation.get('risk_score', 0)
            
            elif input_type == "file_path":
                path_validation = self.validate_file_path(input_data)
                result['warnings'].extend(path_validation.get('warnings', []))
                result['errors'].extend(path_validation.get('errors', []))
                risk_score += path_validation.get('risk_score', 0)
            
            elif input_type == "xml":
                xml_validation = self.validate_xml_content(input_data)
                result['warnings'].extend(xml_validation.get('warnings', []))
                result['errors'].extend(xml_validation.get('errors', []))
                risk_score += xml_validation.get('risk_score', 0)
            
            # Set result
            result['valid'] = len(result['errors']) == 0
            result['sanitized'] = sanitized
            result['risk_score'] = min(risk_score, 100)
            
            # Audit log
            self._audit_log(
                "input_validation",
                {
                    'input_type': input_type,
                    'input_length': len(input_data),
                    'risk_score': result['risk_score'],
                    'warnings_count': len(result['warnings']),
                    'errors_count': len(result['errors'])
                },
                "high" if result['risk_score'] > 50 else "medium" if result['risk_score'] > 20 else "low"
            )
            
        except Exception as e:
            result['errors'].append(f"Validation error: {str(e)}")
            self.logger.error("Input validation failed", error=str(e), input_type=input_type)
        
        return result
    
    def _sanitize_by_type(self, input_data: str, input_type: str) -> str:
        """Sanitize input based on type"""
        sanitized = input_data.strip()
        
        if input_type == "text":
            # Remove potentially dangerous characters
            sanitized = re.sub(r'[<>"\']', '', sanitized)
            sanitized = re.sub(r'<script.*?</script>', '', sanitized, flags=re.IGNORECASE)
        
        elif input_type == "url":
            # URL-specific sanitization
            sanitized = re.sub(r'javascript:', '', sanitized, flags=re.IGNORECASE)
            sanitized = re.sub(r'data:', '', sanitized, flags=re.IGNORECASE)
            sanitized = re.sub(r'vbscript:', '', sanitized, flags=re.IGNORECASE)
        
        elif input_type == "file_path":
            # Path-specific sanitization
            sanitized = re.sub(r'[<>:"|?*]', '', sanitized)  # Remove invalid path characters
            sanitized = re.sub(r'\.\./', '', sanitized)  # Remove path traversal
            sanitized = re.sub(r'\.\.\\', '', sanitized)  # Remove path traversal
        
        elif input_type == "xml":
            # XML-specific sanitization
            sanitized = re.sub(r'<!DOCTYPE.*?>', '', sanitized, flags=re.IGNORECASE)
            sanitized = re.sub(r'<!ENTITY.*?>', '', sanitized, flags=re.IGNORECASE)
        
        return sanitized
    
    def validate_file_path(self, file_path: str) -> Dict[str, Any]:
        """Enhanced file path validation"""
        result = {
            'valid': False,
            'errors': [],
            'warnings': [],
            'risk_score': 0
        }
        
        try:
            # Check for path traversal attempts
            if any(pattern in file_path.lower() for pattern in ['..', '//', '\\']):
                result['errors'].append("Path traversal attempt detected")
                result['risk_score'] += 50
            
            # Check for absolute paths (security concern)
            if os.path.isabs(file_path):
                result['warnings'].append("Absolute path detected")
                result['risk_score'] += 20
            
            # Check file extension
            file_ext = Path(file_path).suffix.lower()
            if file_ext not in self.allowed_extensions:
                result['errors'].append(f"Unsupported file extension: {file_ext}")
                result['risk_score'] += 30
            
            # Check if file exists
            if not os.path.exists(file_path):
                result['errors'].append("File does not exist")
                return result
            
            # Check file size
            file_size = os.path.getsize(file_path)
            max_size = self.max_file_sizes.get(file_ext, 10 * 1024 * 1024)  # Default 10MB
            
            if file_size > max_size:
                result['errors'].append(f"File too large: {file_size / 1024 / 1024:.2f}MB (max: {max_size / 1024 / 1024:.2f}MB)")
                result['risk_score'] += 25
            
            # Check file permissions
            if os.access(file_path, os.W_OK):
                result['warnings'].append("File is writable")
                result['risk_score'] += 10
            
            result['valid'] = len(result['errors']) == 0
            result['file_size'] = file_size
            result['file_extension'] = file_ext
            
        except Exception as e:
            result['errors'].append(f"File validation error: {str(e)}")
        
        return result
    
    def validate_url(self, url: str) -> Dict[str, Any]:
        """Enhanced URL validation"""
        result = {
            'valid': False,
            'errors': [],
            'warnings': [],
            'risk_score': 0
        }
        
        try:
            parsed = urlparse(url)
            
            # Check for allowed schemes
            if parsed.scheme not in ['http', 'https']:
                result['errors'].append("Invalid URL scheme")
                result['risk_score'] += 30
            
            # Check for blocked patterns
            blocked_patterns = [
                r'javascript:', r'data:', r'vbscript:', r'<script',
                r'onload=', r'onerror=', r'<iframe', r'<object'
            ]
            
            for pattern in blocked_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    result['errors'].append(f"Blocked pattern detected: {pattern}")
                    result['risk_score'] += 40
            
            # Check for suspicious domains
            suspicious_domains = ['localhost', '127.0.0.1', '0.0.0.0', '::1']
            if parsed.hostname in suspicious_domains:
                result['warnings'].append("Suspicious domain detected")
                result['risk_score'] += 20
            
            result['valid'] = len(result['errors']) == 0
            
        except Exception as e:
            result['errors'].append(f"Invalid URL format: {e}")
        
        return result
    
    def validate_xml_content(self, xml_content: str) -> Dict[str, Any]:
        """Enhanced XML content validation"""
        result = {
            'valid': False,
            'errors': [],
            'warnings': [],
            'risk_score': 0
        }
        
        if not xml_content:
            result['errors'].append("XML content is required")
            return result
        
        # Check for XXE attacks
        xxe_patterns = [
            r'<!DOCTYPE.*SYSTEM',
            r'<!ENTITY.*SYSTEM',
            r'<!ENTITY.*PUBLIC',
            r'<!ELEMENT.*SYSTEM'
        ]
        
        for pattern in xxe_patterns:
            if re.search(pattern, xml_content, re.IGNORECASE):
                result['errors'].append("Potentially dangerous XML content detected (XXE)")
                result['risk_score'] += 50
        
        # Check for script injection
        script_patterns = [
            r'<script', r'javascript:', r'vbscript:', r'onload=',
            r'onerror=', r'<iframe', r'<object', r'<embed'
        ]
        
        for pattern in script_patterns:
            if re.search(pattern, xml_content, re.IGNORECASE):
                result['warnings'].append("Script-like content detected in XML")
                result['risk_score'] += 20
        
        # Check for oversized XML
        if len(xml_content) > 50 * 1024 * 1024:  # 50MB
            result['errors'].append("XML content too large")
            result['risk_score'] += 30
        
        result['valid'] = len(result['errors']) == 0
        return result
    
    def validate_api_key(self, api_key: str, service: str) -> Dict[str, Any]:
        """Validate API key format and security"""
        result = {
            'valid': True,
            'errors': [],
            'warnings': []
        }
        
        if not api_key:
            result['valid'] = False
            result['errors'].append("API key cannot be empty")
            return result
        
        # Check minimum length
        if len(api_key) < 10:
            result['valid'] = False
            result['errors'].append("API key too short (minimum 10 characters)")
        
        # Check for common patterns
        if api_key.lower() in ['test', 'demo', 'example', 'sample']:
            result['warnings'].append("API key appears to be a test/demo key")
        
        # Log validation attempt
        self._audit_log("api_key_validation", {
            'service': service,
            'key_length': len(api_key),
            'valid': result['valid']
        })
        
        return result
    
    def validate_ip_address(self, ip_address: str) -> Dict[str, Any]:
        """Validate IP address format and security"""
        result = {
            'valid': True,
            'errors': [],
            'warnings': []
        }
        
        if not ip_address:
            result['valid'] = False
            result['errors'].append("IP address cannot be empty")
            return result
        
        try:
            # Parse IP address
            ip = ipaddress.ip_address(ip_address)
            
            # Check for private IP ranges
            if ip.is_private:
                result['warnings'].append("IP address is in private range")
            
            # Check for loopback
            if ip.is_loopback:
                result['warnings'].append("IP address is loopback")
            
            # Check for multicast
            if ip.is_multicast:
                result['warnings'].append("IP address is multicast")
            
            # Check for reserved ranges
            if ip.is_reserved:
                result['warnings'].append("IP address is in reserved range")
            
        except ValueError as e:
            result['valid'] = False
            result['errors'].append(f"Invalid IP address format: {str(e)}")
        
        # Log validation attempt
        self._audit_log("ip_address_validation", {
            'ip_address': ip_address,
            'valid': result['valid']
        })
        
        return result
    
    def encrypt_sensitive_data(self, data: str) -> Optional[str]:
        """Encrypt sensitive data"""
        if not self.cipher:
            return None
        
        try:
            encrypted = self.cipher.encrypt(data.encode())
            return encrypted.decode()
        except Exception as e:
            self.logger.error("Failed to encrypt data", error=str(e))
            return None
    
    def decrypt_sensitive_data(self, encrypted_data: str) -> Optional[str]:
        """Decrypt sensitive data"""
        if not self.cipher:
            return None
        
        try:
            decrypted = self.cipher.decrypt(encrypted_data.encode())
            return decrypted.decode()
        except Exception as e:
            self.logger.error("Failed to decrypt data", error=str(e))
            return None
    
    def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent audit log entries"""
        return self.audit_log[-limit:] if self.audit_log else []
    
    def export_audit_log(self, file_path: str):
        """Export audit log to file"""
        try:
            with open(file_path, 'w') as f:
                json.dump(self.audit_log, f, indent=2)
            self.logger.info("Audit log exported", file_path=file_path)
        except Exception as e:
            self.logger.error("Failed to export audit log", error=str(e))
    
    def clear_audit_log(self):
        """Clear audit log"""
        self.audit_log.clear()
        self.logger.info("Audit log cleared")

# Global security validator instance
_security_validator = None

def get_security_validator() -> EnhancedSecurityValidator:
    """Get the global security validator instance"""
    global _security_validator
    if _security_validator is None:
        _security_validator = EnhancedSecurityValidator()
    return _security_validator 