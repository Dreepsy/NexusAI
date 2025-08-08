"""
NEXUS-AI: Advanced AI-Powered Network Security Analysis Platform
A sophisticated cybersecurity companion that learns, adapts, and protects.

This platform combines cutting-edge machine learning with real-time threat intelligence
to provide comprehensive network security analysis and automated threat response.
"""

__version__ = "2.0.0"
__author__ = "NEXUS-AI Development Team"
__description__ = "Advanced AI-powered network security analysis with multi-dataset ensemble learning and threat intelligence"
__license__ = "MIT"
__url__ = "https://github.com/Dreepsy/Project_Nexus"

# Import main components for easy access
try:
    from .core.main import EnhancedAITrainer
    from .ai.threat_feeds import enrich_cves_with_threat_intel
    from .cli.commands import main as cli_main
    from .ai.advanced_threat_intel import AdvancedThreatIntel
    from .ai.real_time_learning import RealTimeLearning
    from .security.security_validator_enhanced import EnhancedSecurityValidator
    from .monitoring.health_check import HealthMonitor
    from .optimization.cache_manager import CacheManager
    
    __all__ = [
        "EnhancedAITrainer",
        "enrich_cves_with_threat_intel", 
        "cli_main",
        "AdvancedThreatIntel",
        "RealTimeLearning",
        "EnhancedSecurityValidator",
        "HealthMonitor",
        "CacheManager"
    ]
except ImportError as e:
    # Handle case where modules aren't available yet
    import logging
    logging.warning(f"Some NexusAI modules could not be imported: {e}")
    __all__ = []

# Version info for compatibility checks
def get_version_info():
    """Get detailed version information"""
    return {
        "version": __version__,
        "author": __author__,
        "description": __description__,
        "license": __license__,
        "url": __url__
    }

# Compatibility check
def check_compatibility():
    """Check system compatibility"""
    import sys
    import platform
    
    python_version = sys.version_info
    if python_version < (3, 8):
        raise RuntimeError("NexusAI requires Python 3.8 or higher")
    
    return {
        "python_version": f"{python_version.major}.{python_version.minor}.{python_version.micro}",
        "platform": platform.platform(),
        "architecture": platform.architecture()[0],
        "compatible": True
    } 