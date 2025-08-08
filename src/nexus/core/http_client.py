"""
NEXUS-AI HTTP Client
Provides robust HTTP client with connection pooling, caching, rate limiting, and error recovery
"""

import asyncio
import time
import json
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime, timedelta
import httpx
import aiohttp
from ratelimit import limits, sleep_and_retry
from diskcache import Cache
from ..core.config import get_config, get_logger

logger = get_logger()

@dataclass
class RateLimitConfig:
    """Rate limit configuration for different APIs"""
    calls: int
    period: int  # in seconds
    service: str

class HTTPClient:
    """Robust HTTP client with connection pooling, caching, and rate limiting"""
    
    def __init__(self):
        self.config = get_config()
        self.logger = get_logger()
        
        # Initialize cache
        self.cache = Cache('cache/http_requests')
        
        # Rate limit configurations
        self.rate_limits = {
            'virustotal': RateLimitConfig(4, 60, 'virustotal'),  # 4 calls per minute
            'shodan': RateLimitConfig(1, 1, 'shodan'),           # 1 call per second
            'nvd': RateLimitConfig(5, 30, 'nvd'),                # 5 calls per 30 seconds
            'cisa': RateLimitConfig(10, 60, 'cisa'),             # 10 calls per minute
        }
        
        # Initialize connection pools
        self._setup_connection_pools()
    
    def _setup_connection_pools(self):
        """Setup connection pools for different services"""
        # Async client for high-performance requests
        self.async_client = None  # Will be initialized when needed
        
        # Sync client with connection pooling
        limits = httpx.Limits(max_keepalive_connections=20, max_connections=100)
        timeout = httpx.Timeout(30.0, connect=10.0)
        
        self.sync_client = httpx.Client(
            limits=limits,
            timeout=timeout,
            headers={
                'User-Agent': 'NEXUS-AI/1.0.0 (Security Analysis Tool)'
            }
        )
    
    async def _get_async_client(self) -> aiohttp.ClientSession:
        """Get or create async HTTP client"""
        if self.async_client is None or self.async_client.closed:
            connector = aiohttp.TCPConnector(
                limit=100,
                limit_per_host=30,
                ttl_dns_cache=300,
                use_dns_cache=True
            )
            self.async_client = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=30)
            )
        return self.async_client
    
    def _get_cache_key(self, url: str, params: Dict[str, Any] = None) -> str:
        """Generate cache key for request"""
        cache_data = {
            'url': url,
            'params': params or {}
        }
        return f"http_request:{hash(json.dumps(cache_data, sort_keys=True))}"
    
    def _is_cacheable(self, method: str, url: str) -> bool:
        """Check if request is cacheable"""
        return method.upper() == 'GET' and any(
            service in url.lower() for service in ['virustotal', 'shodan', 'nvd', 'cisa']
        )
    
    def _get_cache_ttl(self, service: str) -> int:
        """Get cache TTL for different services"""
        ttl_map = {
            'virustotal': 3600,    # 1 hour
            'shodan': 1800,        # 30 minutes
            'nvd': 7200,           # 2 hours
            'cisa': 86400,         # 24 hours
        }
        return ttl_map.get(service, 1800)
    
    def _get_service_from_url(self, url: str) -> str:
        """Extract service name from URL"""
        url_lower = url.lower()
        if 'virustotal' in url_lower:
            return 'virustotal'
        elif 'shodan' in url_lower:
            return 'shodan'
        elif 'nvd' in url_lower:
            return 'nvd'
        elif 'cisa' in url_lower:
            return 'cisa'
        return 'default'
    
    @sleep_and_retry
    @limits(calls=4, period=60)
    def _rate_limited_request(self, service: str, func, *args, **kwargs):
        """Execute rate-limited request"""
        return func(*args, **kwargs)
    
    def _handle_error_response(self, response: httpx.Response, service: str) -> Dict[str, Any]:
        """Handle error responses with proper logging"""
        error_info = {
            'status_code': response.status_code,
            'service': service,
            'url': str(response.url),
            'error': True
        }
        
        if response.status_code == 429:
            error_info['error_type'] = 'rate_limit_exceeded'
            error_info['message'] = f'Rate limit exceeded for {service}'
            self.logger.warning("Rate limit exceeded", **error_info)
        elif response.status_code == 401:
            error_info['error_type'] = 'unauthorized'
            error_info['message'] = f'Invalid API key for {service}'
            self.logger.error("Invalid API key", **error_info)
        elif response.status_code == 403:
            error_info['error_type'] = 'forbidden'
            error_info['message'] = f'Access forbidden for {service}'
            self.logger.error("Access forbidden", **error_info)
        elif response.status_code >= 500:
            error_info['error_type'] = 'server_error'
            error_info['message'] = f'Server error for {service}'
            self.logger.error("Server error", **error_info)
        else:
            error_info['error_type'] = 'http_error'
            error_info['message'] = f'HTTP error {response.status_code} for {service}'
            self.logger.error("HTTP error", **error_info)
        
        return error_info
    
    def get(self, url: str, params: Dict[str, Any] = None, 
            headers: Dict[str, str] = None, cache: bool = True) -> Dict[str, Any]:
        """Make GET request with caching and error handling"""
        service = self._get_service_from_url(url)
        cache_key = self._get_cache_key(url, params) if cache and self._is_cacheable('GET', url) else None
        
        # Check cache first
        if cache_key and cache:
            cached_response = self.cache.get(cache_key)
            if cached_response:
                self.logger.debug("Cache hit", service=service, url=url)
                return cached_response
        
        try:
            # Make rate-limited request
            response = self._rate_limited_request(
                service,
                self.sync_client.get,
                url,
                params=params,
                headers=headers
            )
            
            # Handle response
            if response.status_code == 200:
                data = response.json() if 'application/json' in response.headers.get('content-type', '') else response.text
                result = {'data': data, 'status_code': 200, 'error': False}
                
                # Cache successful response
                if cache_key and cache:
                    ttl = self._get_cache_ttl(service)
                    self.cache.set(cache_key, result, expire=ttl)
                    self.logger.debug("Cached response", service=service, url=url, ttl=ttl)
                
                return result
            else:
                return self._handle_error_response(response, service)
                
        except httpx.TimeoutException:
            error_info = {
                'error': True,
                'error_type': 'timeout',
                'message': f'Request timeout for {service}',
                'service': service,
                'url': url
            }
            self.logger.error("Request timeout", **error_info)
            return error_info
            
        except httpx.ConnectError:
            error_info = {
                'error': True,
                'error_type': 'connection_error',
                'message': f'Connection error for {service}',
                'service': service,
                'url': url
            }
            self.logger.error("Connection error", **error_info)
            return error_info
            
        except Exception as e:
            error_info = {
                'error': True,
                'error_type': 'unknown_error',
                'message': str(e),
                'service': service,
                'url': url
            }
            self.logger.error("Unknown error", **error_info)
            return error_info
    
    async def aget(self, url: str, params: Dict[str, Any] = None,
                   headers: Dict[str, str] = None, cache: bool = True) -> Dict[str, Any]:
        """Make async GET request"""
        service = self._get_service_from_url(url)
        cache_key = self._get_cache_key(url, params) if cache and self._is_cacheable('GET', url) else None
        
        # Check cache first
        if cache_key and cache:
            cached_response = self.cache.get(cache_key)
            if cached_response:
                self.logger.debug("Cache hit (async)", service=service, url=url)
                return cached_response
        
        try:
            async_client = await self._get_async_client()
            
            # Make rate-limited request
            response = await self._rate_limited_request(
                service,
                async_client.get,
                url,
                params=params,
                headers=headers
            )
            
            # Handle response
            if response.status == 200:
                data = await response.json() if 'application/json' in response.headers.get('content-type', '') else await response.text()
                result = {'data': data, 'status_code': 200, 'error': False}
                
                # Cache successful response
                if cache_key and cache:
                    ttl = self._get_cache_ttl(service)
                    self.cache.set(cache_key, result, expire=ttl)
                    self.logger.debug("Cached response (async)", service=service, url=url, ttl=ttl)
                
                return result
            else:
                error_info = {
                    'error': True,
                    'error_type': 'http_error',
                    'status_code': response.status,
                    'message': f'HTTP error {response.status} for {service}',
                    'service': service,
                    'url': url
                }
                self.logger.error("HTTP error (async)", **error_info)
                return error_info
                
        except asyncio.TimeoutError:
            error_info = {
                'error': True,
                'error_type': 'timeout',
                'message': f'Request timeout for {service}',
                'service': service,
                'url': url
            }
            self.logger.error("Request timeout (async)", **error_info)
            return error_info
            
        except Exception as e:
            error_info = {
                'error': True,
                'error_type': 'unknown_error',
                'message': str(e),
                'service': service,
                'url': url
            }
            self.logger.error("Unknown error (async)", **error_info)
            return error_info
    
    def post(self, url: str, data: Dict[str, Any] = None, 
             headers: Dict[str, str] = None) -> Dict[str, Any]:
        """Make POST request with error handling"""
        service = self._get_service_from_url(url)
        
        try:
            response = self._rate_limited_request(
                service,
                self.sync_client.post,
                url,
                json=data,
                headers=headers
            )
            
            if response.status_code == 200:
                return {
                    'data': response.json(),
                    'status_code': 200,
                    'error': False
                }
            else:
                return self._handle_error_response(response, service)
                
        except Exception as e:
            error_info = {
                'error': True,
                'error_type': 'unknown_error',
                'message': str(e),
                'service': service,
                'url': url
            }
            self.logger.error("POST request error", **error_info)
            return error_info
    
    def clear_cache(self, service: str = None):
        """Clear cache for specific service or all"""
        if service:
            # Clear cache for specific service
            keys_to_delete = []
            for key in self.cache.iterkeys():
                if service in key:
                    keys_to_delete.append(key)
            
            for key in keys_to_delete:
                self.cache.delete(key)
            
            self.logger.info("Cache cleared", service=service, keys_cleared=len(keys_to_delete))
        else:
            # Clear all cache
            self.cache.clear()
            self.logger.info("All cache cleared")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            'size': len(self.cache),
            'volume': self.cache.volume(),
            'hits': self.cache.stats(enable=True)['hits'],
            'misses': self.cache.stats(enable=True)['misses']
        }
    
    def close(self):
        """Close HTTP clients and cleanup"""
        if self.sync_client:
            self.sync_client.close()
        
        if self.async_client and not self.async_client.closed:
            asyncio.create_task(self.async_client.close())
        
        self.cache.close()

# Global HTTP client instance
_http_client = None

def get_http_client() -> HTTPClient:
    """Get the global HTTP client instance"""
    global _http_client
    if _http_client is None:
        _http_client = HTTPClient()
    return _http_client 