#!/usr/bin/env python3
"""
NEXUS-AI Cache Manager
Advanced caching system for performance optimization

TODO: The cache cleanup sometimes takes too long on large datasets
TODO: Need to implement better memory management for large objects
TODO: The serialization can fail on some complex objects
TODO: The cache sometimes gets corrupted, need better recovery
TODO: Should probably add compression for large objects
"""

import os
import json
import pickle
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Union
from functools import wraps
import threading
import logging

from ..core.config import get_config, get_logger

# Get configuration and logger
config = get_config()
logger = get_logger()

class CacheManager:
    """Advanced caching system for NEXUS-AI"""
    
    def __init__(self, cache_dir: str = "cache"):
        self.cache_dir = cache_dir
        self.memory_cache = {}
        self.cache_stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'size': 0
        }
        self._lock = threading.Lock()
        
        # Ensure cache directory exists
        os.makedirs(cache_dir, exist_ok=True)
        
        # Load cache configuration
        self.max_memory_size = config.get('performance.max_memory_usage', '1GB')
        self.max_disk_size = config.get('performance.max_disk_size', '10GB')
        self.default_ttl = config.get('performance.cache_ttl', 3600)
        
        # Start cleanup thread
        self._start_cleanup_thread()
    
    def _get_cache_key(self, key: str, namespace: str = "default") -> str:
        """Generate cache key with namespace"""
        return f"{namespace}:{key}"
    
    def _get_file_path(self, cache_key: str) -> str:
        """Get file path for cache entry"""
        # Create hash for filename
        key_hash = hashlib.md5(cache_key.encode()).hexdigest()
        return os.path.join(self.cache_dir, f"{key_hash}.cache")
    
    def _serialize_data(self, data: Any) -> bytes:
        """Serialize data for storage"""
        try:
            # Handle bytes objects specially
            if isinstance(data, bytes):
                return data
            return pickle.dumps(data)
        except Exception as e:
            logger.error("Failed to serialize cache data", error=str(e))
            try:
                            # Use a more robust JSON serialization with custom encoder
            # This fallback isn't perfect but it's better than crashing
            # Sometimes pickle just doesn't work with complex objects
                return json.dumps(data, default=self._json_serializer).encode()
            except Exception:
                # Last resort - just convert to string
                # This is pretty hacky but it works
                return str(data).encode()
    
    def _json_serializer(self, obj):
        """Custom JSON serializer for complex objects"""
        if isinstance(obj, bytes):
            return obj.decode('utf-8', errors='ignore')
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes, list, dict)):
            return list(obj)
        else:
            return str(obj)
    
    def _deserialize_data(self, data: bytes) -> Any:
        """Deserialize data from storage"""
        try:
            return pickle.loads(data)
        except Exception:
            try:
                return json.loads(data.decode())
            except Exception as e:
                logger.error("Failed to deserialize cache data", error=str(e))
                return None
    
    def get(self, key: str, namespace: str = "default") -> Optional[Any]:
        """Get value from cache"""
        cache_key = self._get_cache_key(key, namespace)
        
        with self._lock:
            # Check memory cache first
            if cache_key in self.memory_cache:
                entry = self.memory_cache[cache_key]
                if entry['expires_at'] > datetime.now():
                    self.cache_stats['hits'] += 1
                    return entry['data']
                else:
                    # Expired entry
                    del self.memory_cache[cache_key]
            
            # Check disk cache
            file_path = self._get_file_path(cache_key)
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'rb') as f:
                        file_content = f.read()
                        if not file_content:
                            # Empty file, remove it
                            os.remove(file_path)
                            return None
                        
                        entry_data = json.loads(file_content.decode())
                    
                    # Check expiration
                    if entry_data.get('expires_at'):
                        expires_at = datetime.fromisoformat(entry_data['expires_at'])
                        if expires_at > datetime.now():
                            # Valid entry, add to memory cache
                            self.memory_cache[cache_key] = {
                                'data': entry_data['data'],
                                'expires_at': expires_at
                            }
                            self.cache_stats['hits'] += 1
                            return entry_data['data']
                        else:
                            # Expired entry, remove file
                            os.remove(file_path)
                    else:
                        # No expiration, treat as valid
                        self.memory_cache[cache_key] = {
                            'data': entry_data['data'],
                            'expires_at': datetime.now() + timedelta(hours=1)
                        }
                        self.cache_stats['hits'] += 1
                        return entry_data['data']
                        
                except (json.JSONDecodeError, ValueError, KeyError, UnicodeDecodeError) as e:
                    # Corrupted file, remove it silently
                    try:
                        os.remove(file_path)
                    except OSError:
                        pass
                    return None
                except Exception as e:
                    # Only log unexpected errors
                    logger.debug(f"Cache read error: {e}")
                    return None
            
            self.cache_stats['misses'] += 1
            return None
    
    def set(self, key: str, value: Any, ttl: int = None, namespace: str = "default") -> bool:
        """Set value in cache"""
        if ttl is None:
            ttl = self.default_ttl
        
        cache_key = self._get_cache_key(key, namespace)
        expires_at = datetime.now() + timedelta(seconds=ttl)
        created_at = datetime.now()
        
        # Serialize data
        serialized_data = self._serialize_data(value)
        
        # Store in memory cache
        with self._lock:
            self.memory_cache[cache_key] = {
                'data': value,
                'expires_at': expires_at,
                'created_at': created_at
            }
        
        # Store on disk
        try:
            file_path = self._get_file_path(cache_key)
            entry_data = {
                'data': value,  # Store the original value, not serialized
                'expires_at': expires_at.isoformat(),
                'created_at': created_at.isoformat(),
                'namespace': namespace,
                'key': key
            }
            
            with open(file_path, 'wb') as f:
                f.write(json.dumps(entry_data, default=self._json_serializer).encode())
            
            return True
            
        except Exception as e:
            # Only log if it's not a serialization error
            if "Object of type bytes is not JSON serializable" not in str(e):
                logger.error("Failed to write cache file", error=str(e))
            return False
    
    def delete(self, key: str, namespace: str = "default") -> bool:
        """Delete cache entry"""
        cache_key = self._get_cache_key(key, namespace)
        
        with self._lock:
            # Remove from memory cache
            if cache_key in self.memory_cache:
                del self.memory_cache[cache_key]
            
            # Remove from disk
            file_path = self._get_file_path(cache_key)
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    return True
                except Exception as e:
                    logger.error("Failed to delete cache file", error=str(e))
                    return False
        
        return True
    
    def clear(self, namespace: str = None):
        """Clear cache entries"""
        with self._lock:
            if namespace:
                # Clear specific namespace
                keys_to_remove = []
                for key in self.memory_cache.keys():
                    if key.startswith(f"{namespace}:"):
                        keys_to_remove.append(key)
                
                for key in keys_to_remove:
                    del self.memory_cache[key]
                    file_path = self._get_file_path(key)
                    if os.path.exists(file_path):
                        os.remove(file_path)
            else:
                # Clear all
                self.memory_cache.clear()
                for filename in os.listdir(self.cache_dir):
                    if filename.endswith('.cache'):
                        os.remove(os.path.join(self.cache_dir, filename))
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            return {
                'memory_entries': len(self.memory_cache),
                'disk_entries': len([f for f in os.listdir(self.cache_dir) if f.endswith('.cache')]),
                'hits': self.cache_stats['hits'],
                'misses': self.cache_stats['misses'],
                'hit_rate': self.cache_stats['hits'] / (self.cache_stats['hits'] + self.cache_stats['misses']) if (self.cache_stats['hits'] + self.cache_stats['misses']) > 0 else 0,
                'evictions': self.cache_stats['evictions']
            }
    
    def _cleanup_expired(self):
        """Clean up expired cache entries"""
        current_time = datetime.now()
        
        with self._lock:
            # Clean memory cache
            keys_to_remove = []
            for key, entry in self.memory_cache.items():
                if entry['expires_at'] <= current_time:
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                del self.memory_cache[key]
                self.cache_stats['evictions'] += 1
            
            # Clean disk cache
            for filename in os.listdir(self.cache_dir):
                if filename.endswith('.cache'):
                    file_path = os.path.join(self.cache_dir, filename)
                    try:
                        with open(file_path, 'rb') as f:
                            entry_data = json.loads(f.read().decode())
                        
                        expires_at = datetime.fromisoformat(entry_data['expires_at'])
                        if expires_at <= current_time:
                            os.remove(file_path)
                            self.cache_stats['evictions'] += 1
                    
                    except Exception as e:
                        logger.error("Failed to read cache file during cleanup", error=str(e))
                        # Remove corrupted file
                        if os.path.exists(file_path):
                            os.remove(file_path)
    
    def _start_cleanup_thread(self):
        """Start background cleanup thread"""
        def cleanup_loop():
            while True:
                try:
                    self._cleanup_expired()
                    time.sleep(300)  # Run every 5 minutes
                except Exception as e:
                    logger.error("Cache cleanup error", error=str(e))
                    time.sleep(300)
        
        cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        cleanup_thread.start()

# Global cache manager instance
_cache_manager = None

def get_cache_manager() -> CacheManager:
    """Get the global cache manager instance"""
    global _cache_manager
    if _cache_manager is None:
        _cache_manager = CacheManager()
    return _cache_manager

def cached(ttl: int = None, namespace: str = "default"):
    """Decorator for caching function results"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            cache_manager = get_cache_manager()
            
            # Create cache key from function name and arguments
            key_parts = [func.__name__]
            key_parts.extend([str(arg) for arg in args])
            key_parts.extend([f"{k}={v}" for k, v in sorted(kwargs.items())])
            cache_key = ":".join(key_parts)
            
            # Try to get from cache
            cached_result = cache_manager.get(cache_key, namespace)
            if cached_result is not None:
                return cached_result
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            cache_manager.set(cache_key, result, ttl, namespace)
            
            return result
        return wrapper
    return decorator

# Example usage
if __name__ == "__main__":
    # Test cache manager
    cache = get_cache_manager()
    
    # Test basic operations
    cache.set("test_key", "test_value", ttl=60)
    result = cache.get("test_key")
    print(f"Cached value: {result}")
    
    # Test decorator
    @cached(ttl=300, namespace="api")
    def expensive_api_call(param):
        print(f"Making expensive API call with param: {param}")
        return f"result_for_{param}"
    
    # First call (cache miss)
    result1 = expensive_api_call("test")
    # Second call (cache hit)
    result2 = expensive_api_call("test")
    
    print(f"Results: {result1}, {result2}")
    
    # Print stats
    stats = cache.get_stats()
    print(f"Cache stats: {stats}") 