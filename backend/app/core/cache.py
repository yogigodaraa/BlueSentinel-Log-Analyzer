"""
Caching Layer
Redis-based caching with fallback to in-memory
"""

import json
import hashlib
from typing import Optional, Any, Callable
from functools import wraps

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class CacheManager:
    """Unified cache manager with Redis and in-memory fallback"""
    
    def __init__(self):
        self.redis_client: Optional[redis.Redis] = None
        self.memory_cache: dict = {}
        self._initialized = False
    
    async def initialize(self):
        """Initialize cache connections"""
        if self._initialized:
            return
        
        if REDIS_AVAILABLE and settings.REDIS_URL:
            try:
                self.redis_client = redis.from_url(
                    settings.REDIS_URL,
                    encoding="utf-8",
                    decode_responses=True
                )
                await self.redis_client.ping()
                logger.info("Redis cache initialized successfully")
            except Exception as e:
                logger.warning(f"Redis unavailable, using in-memory cache: {e}")
                self.redis_client = None
        else:
            logger.info("Using in-memory cache (Redis not available)")
        
        self._initialized = True
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        try:
            if self.redis_client:
                value = await self.redis_client.get(key)
                if value:
                    return json.loads(value)
            else:
                return self.memory_cache.get(key)
        except Exception as e:
            logger.error(f"Cache get error: {e}")
        return None
    
    async def set(
        self,
        key: str,
        value: Any,
        expiry: Optional[int] = None
    ):
        """Set value in cache with optional expiry (seconds)"""
        try:
            serialized = json.dumps(value)
            
            if self.redis_client:
                if expiry:
                    await self.redis_client.setex(key, expiry, serialized)
                else:
                    await self.redis_client.set(key, serialized)
            else:
                self.memory_cache[key] = value
                # Simple expiry for in-memory (would need background task for cleanup)
        except Exception as e:
            logger.error(f"Cache set error: {e}")
    
    async def delete(self, key: str):
        """Delete key from cache"""
        try:
            if self.redis_client:
                await self.redis_client.delete(key)
            else:
                self.memory_cache.pop(key, None)
        except Exception as e:
            logger.error(f"Cache delete error: {e}")
    
    async def clear(self):
        """Clear all cache"""
        try:
            if self.redis_client:
                await self.redis_client.flushdb()
            else:
                self.memory_cache.clear()
        except Exception as e:
            logger.error(f"Cache clear error: {e}")
    
    def generate_key(self, prefix: str, *args, **kwargs) -> str:
        """Generate cache key from arguments"""
        key_data = f"{prefix}:{args}:{sorted(kwargs.items())}"
        return hashlib.md5(key_data.encode()).hexdigest()


# Global cache instance
cache_manager = CacheManager()


def cached(
    prefix: str,
    expiry: int = 300,  # 5 minutes default
    key_builder: Optional[Callable] = None
):
    """
    Decorator for caching function results
    
    Args:
        prefix: Cache key prefix
        expiry: Cache expiration in seconds
        key_builder: Custom function to build cache key
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Build cache key
            if key_builder:
                cache_key = key_builder(*args, **kwargs)
            else:
                cache_key = cache_manager.generate_key(prefix, *args, **kwargs)
            
            # Try to get from cache
            cached_value = await cache_manager.get(cache_key)
            if cached_value is not None:
                logger.debug(f"Cache hit: {cache_key}")
                return cached_value
            
            # Execute function
            logger.debug(f"Cache miss: {cache_key}")
            result = await func(*args, **kwargs)
            
            # Store in cache
            await cache_manager.set(cache_key, result, expiry)
            
            return result
        
        return wrapper
    return decorator


async def init_cache():
    """Initialize cache system"""
    await cache_manager.initialize()
