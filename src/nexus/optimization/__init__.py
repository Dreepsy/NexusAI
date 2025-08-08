"""
Optimization components for NEXUS-AI
"""

try:
    from .cache_manager import CacheManager
    
    __all__ = [
        "CacheManager"
    ]
except ImportError:
    # Handle case where modules aren't available yet
    __all__ = []
