#!/usr/bin/env python3
"""
NEXUS-AI Health Monitoring System
Provides comprehensive health checks and monitoring capabilities
"""

import os
import psutil
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import threading
import logging
import sys

from ..core.config import get_config, get_logger
from ..security.security_validator_enhanced import get_security_validator

# Get configuration and logger
config = get_config()
logger = get_logger()

class HealthMonitor:
    """Comprehensive health monitoring for NEXUS-AI"""
    
    def __init__(self):
        self.start_time = datetime.now()
        self.health_checks = {}
        self.metrics = {}
        self.alerts = []
        self._monitoring_thread = None
        self._stop_monitoring = False
    
    def check_system_resources(self) -> Dict[str, Any]:
        """Check system resource usage"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_available': memory.available,
                'disk_percent': disk.percent,
                'disk_free': disk.free,
                'status': 'healthy' if cpu_percent < 90 and memory.percent < 90 else 'warning'
            }
        except Exception as e:
            logger.error("System resource check failed", error=str(e))
            return {'status': 'error', 'error': str(e)}
    
    def check_model_status(self) -> Dict[str, Any]:
        """Check AI model status and performance"""
        try:
            from ..cli.predictor import get_model_info, validate_model_compatibility
            
            model_info = get_model_info()
            is_compatible = validate_model_compatibility(model_info)
            
            return {
                'status': 'loaded' if model_info else 'not_loaded',
                'model_info': model_info,
                'compatible': is_compatible,
                'last_check': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error("Model status check failed", error=str(e))
            return {'status': 'error', 'error': str(e)}
    
    def check_api_keys(self) -> Dict[str, Any]:
        """Check API key configuration"""
        try:
            api_keys = {
                'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
                'shodan': os.getenv('SHODAN_API_KEY'),
                'deepseek': os.getenv('DEEPSEEK_API_KEY'),
                'abuseipdb': os.getenv('ABUSEIPDB_API_KEY'),
                'otx': os.getenv('OTX_API_KEY')
            }
            
            configured_keys = {k: bool(v) for k, v in api_keys.items()}
            total_configured = sum(configured_keys.values())
            
            return {
                'configured_keys': configured_keys,
                'total_configured': total_configured,
                'status': 'healthy' if total_configured >= 2 else 'warning'
            }
        except Exception as e:
            logger.error("API key check failed", error=str(e))
            return {'status': 'error', 'error': str(e)}
    
    def check_file_system(self) -> Dict[str, Any]:
        """Check file system and required directories"""
        try:
            required_dirs = ['models', 'data', 'logs', 'cache']
            dir_status = {}
            
            for dir_name in required_dirs:
                dir_path = os.path.join(os.getcwd(), dir_name)
                exists = os.path.exists(dir_path)
                writable = os.access(dir_path, os.W_OK) if exists else False
                
                dir_status[dir_name] = {
                    'exists': exists,
                    'writable': writable,
                    'path': dir_path
                }
            
            all_exist = all(status['exists'] for status in dir_status.values())
            all_writable = all(status['writable'] for status in dir_status.values())
            
            return {
                'directories': dir_status,
                'all_exist': all_exist,
                'all_writable': all_writable,
                'status': 'healthy' if all_exist and all_writable else 'warning'
            }
        except Exception as e:
            logger.error("File system check failed", error=str(e))
            return {'status': 'error', 'error': str(e)}
    
    def check_learning_system(self) -> Dict[str, Any]:
        """Check real-time learning system status"""
        try:
            from ..ai.real_time_learning import get_learning_statistics
            
            stats = get_learning_statistics()
            
            return {
                'status': 'active',
                'statistics': stats,
                'last_check': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error("Learning system check failed", error=str(e))
            return {'status': 'error', 'error': str(e)}
    
    def check_security_validator(self) -> Dict[str, Any]:
        """Check security validator status"""
        try:
            validator = get_security_validator()
            
            # Test basic validation
            test_result = validator.validate_ip_address("192.168.1.1")
            
            return {
                'status': 'healthy' if test_result['valid'] else 'error',
                'test_result': test_result,
                'last_check': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error("Security validator check failed", error=str(e))
            return {'status': 'error', 'error': str(e)}
    
    def run_comprehensive_check(self) -> Dict[str, Any]:
        """Run all health checks"""
        start_time = time.time()
        
        checks = {
            'system_resources': self.check_system_resources(),
            'model_status': self.check_model_status(),
            'api_keys': self.check_api_keys(),
            'file_system': self.check_file_system(),
            'learning_system': self.check_learning_system(),
            'security_validator': self.check_security_validator()
        }
        
        # Calculate overall status
        statuses = [check.get('status', 'unknown') for check in checks.values()]
        overall_status = 'healthy'
        
        if 'error' in statuses:
            overall_status = 'error'
        elif 'warning' in statuses:
            overall_status = 'warning'
        
        # Calculate uptime
        uptime = datetime.now() - self.start_time
        
        result = {
            'timestamp': datetime.now().isoformat(),
            'overall_status': overall_status,
            'uptime_seconds': uptime.total_seconds(),
            'uptime_formatted': str(uptime).split('.')[0],
            'checks': checks,
            'response_time_ms': round((time.time() - start_time) * 1000, 2)
        }
        
        # Store metrics
        self.metrics[datetime.now().isoformat()] = result
        
        # Generate alerts if needed
        self._generate_alerts(result)
        
        return result
    
    def _generate_alerts(self, health_result: Dict[str, Any]):
        """Generate alerts based on health check results"""
        alerts = []
        
        # Check for critical issues
        if health_result['overall_status'] == 'error':
            alerts.append({
                'level': 'critical',
                'message': 'System health check failed',
                'timestamp': datetime.now().isoformat(),
                'details': health_result
            })
        
        # Check specific components
        for check_name, check_result in health_result['checks'].items():
            if check_result.get('status') == 'error':
                alerts.append({
                    'level': 'error',
                    'message': f'{check_name} health check failed',
                    'timestamp': datetime.now().isoformat(),
                    'component': check_name,
                    'details': check_result
                })
            elif check_result.get('status') == 'warning':
                alerts.append({
                    'level': 'warning',
                    'message': f'{check_name} showing warning signs',
                    'timestamp': datetime.now().isoformat(),
                    'component': check_name,
                    'details': check_result
                })
        
        # Add new alerts
        self.alerts.extend(alerts)
        
        # Keep only recent alerts (last 24 hours)
        cutoff_time = datetime.now() - timedelta(hours=24)
        self.alerts = [
            alert for alert in self.alerts
            if datetime.fromisoformat(alert['timestamp']) > cutoff_time
        ]
    
    def start_monitoring(self, interval_seconds: int = 60):
        """Start continuous monitoring"""
        if self._monitoring_thread and self._monitoring_thread.is_alive():
            logger.warning("Monitoring already running")
            return
        
        self._stop_monitoring = False
        
        def monitor_loop():
            while not self._stop_monitoring:
                try:
                    self.run_comprehensive_check()
                    time.sleep(interval_seconds)
                except Exception as e:
                    logger.error("Monitoring loop error", error=str(e))
                    time.sleep(interval_seconds)
        
        self._monitoring_thread = threading.Thread(target=monitor_loop, daemon=True)
        self._monitoring_thread.start()
        logger.info("Health monitoring started", interval_seconds=interval_seconds)
    
    def stop_monitoring(self):
        """Stop continuous monitoring"""
        self._stop_monitoring = True
        if self._monitoring_thread:
            self._monitoring_thread.join(timeout=5)
        logger.info("Health monitoring stopped")
    
    def get_metrics(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get historical metrics"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        return [
            metric for timestamp, metric in self.metrics.items()
            if datetime.fromisoformat(timestamp) > cutoff_time
        ]
    
    def get_alerts(self, level: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get alerts, optionally filtered by level"""
        if level:
            return [alert for alert in self.alerts if alert['level'] == level]
        return self.alerts
    
    def export_health_report(self, filepath: str):
        """Export comprehensive health report"""
        try:
            report = {
                'timestamp': datetime.now().isoformat(),
                'current_health': self.run_comprehensive_check(),
                'recent_metrics': self.get_metrics(hours=24),
                'recent_alerts': self.get_alerts(),
                'system_info': {
                    'python_version': sys.version,
                    'platform': sys.platform,
                    'working_directory': os.getcwd(),
                    'environment_variables': dict(os.environ)
                }
            }
            
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            logger.info("Health report exported", filepath=filepath)
            
        except Exception as e:
            logger.error("Failed to export health report", error=str(e))

# Global health monitor instance
_health_monitor = None

def get_health_monitor() -> HealthMonitor:
    """Get the global health monitor instance"""
    global _health_monitor
    if _health_monitor is None:
        _health_monitor = HealthMonitor()
    return _health_monitor

def run_health_check() -> Dict[str, Any]:
    """Run a comprehensive health check"""
    monitor = get_health_monitor()
    return monitor.run_comprehensive_check()

if __name__ == "__main__":
    # Test health monitoring
    monitor = HealthMonitor()
    result = monitor.run_comprehensive_check()
    print(json.dumps(result, indent=2)) 