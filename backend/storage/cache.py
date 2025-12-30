from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, Optional, Callable
from functools import wraps

from ..utils.logging_config import get_logger

logger = get_logger("cache")

class Cache:
    def __init__(self, default_ttl: int = 3600):
        self._cache: Dict[str, tuple[Any, float]] = {}
        self.default_ttl = default_ttl
    
    def get(self, key: str) -> Optional[Any]:
        if key not in self._cache:
            return None
        
        value, expiry = self._cache[key]
        if time.time() > expiry:
            del self._cache[key]
            return None
        
        return value
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        ttl = ttl if ttl is not None else self.default_ttl
        expiry = time.time() + ttl
        self._cache[key] = (value, expiry)
    
    def delete(self, key: str) -> bool:
        if key in self._cache:
            del self._cache[key]
            return True
        return False
    
    def clear(self) -> None:
        self._cache.clear()
    
    def cleanup_expired(self) -> int:
        now = time.time()
        expired = [k for k, (_, expiry) in self._cache.items() if now > expiry]
        for key in expired:
            del self._cache[key]
        return len(expired)
    
    def size(self) -> int:
        return len(self._cache)

class FileCache:
    def __init__(self, cache_dir: Path | str, default_ttl: int = 86400):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.default_ttl = default_ttl
    
    def _get_cache_path(self, key: str) -> Path:
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        return self.cache_dir / f"{key_hash}.cache"
    
    def get(self, key: str) -> Optional[Any]:
        cache_path = self._get_cache_path(key)
        
        if not cache_path.exists():
            return None
        
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if time.time() > data['expiry']:
                cache_path.unlink()
                return None
            
            return data['value']
        except Exception as e:
            logger.warning(f"Failed to read cache file: {e}")
            return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        ttl = ttl if ttl is not None else self.default_ttl
        cache_path = self._get_cache_path(key)
        
        data = {
            'value': value,
            'expiry': time.time() + ttl,
            'created': time.time(),
        }
        
        try:
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(data, f)
        except (TypeError, ValueError) as e:
            logger.warning(f"Failed to serialize cache data: {e}")
        except Exception as e:
            logger.warning(f"Failed to write cache file: {e}")
    
    def delete(self, key: str) -> bool:
        cache_path = self._get_cache_path(key)
        if cache_path.exists():
            cache_path.unlink()
            return True
        return False
    
    def clear(self) -> None:
        for cache_file in self.cache_dir.glob("*.cache"):
            cache_file.unlink()
    
    def cleanup_expired(self) -> int:
        count = 0
        now = time.time()
        
        for cache_file in self.cache_dir.glob("*.cache"):
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                if now > data['expiry']:
                    cache_file.unlink()
                    count += 1
            except Exception:
                cache_file.unlink()
                count += 1
        
        return count

class LRUCache:
    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self._cache: Dict[str, Any] = {}
        self._access_order: list[str] = []
    
    def get(self, key: str) -> Optional[Any]:
        if key not in self._cache:
            return None
        
        self._access_order.remove(key)
        self._access_order.append(key)
        
        return self._cache[key]
    
    def set(self, key: str, value: Any) -> None:
        if key in self._cache:
            self._access_order.remove(key)
        elif len(self._cache) >= self.max_size:
            lru_key = self._access_order.pop(0)
            del self._cache[lru_key]
        
        self._cache[key] = value
        self._access_order.append(key)
    
    def delete(self, key: str) -> bool:
        if key in self._cache:
            del self._cache[key]
            self._access_order.remove(key)
            return True
        return False
    
    def clear(self) -> None:
        self._cache.clear()
        self._access_order.clear()
    
    def size(self) -> int:
        return len(self._cache)

def cached(
    cache_instance: Optional[Cache] = None,
    ttl: Optional[int] = None,
    key_func: Optional[Callable] = None,
):
    if cache_instance is None:
        cache_instance = Cache()
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                key_parts = [func.__name__]
                key_parts.extend(str(arg) for arg in args)
                key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
                cache_key = ":".join(key_parts)
            
            cached_value = cache_instance.get(cache_key)
            if cached_value is not None:
                logger.debug(f"Cache hit for {func.__name__}")
                return cached_value
            
            result = func(*args, **kwargs)
            cache_instance.set(cache_key, result, ttl)
            logger.debug(f"Cache miss for {func.__name__}, cached result")
            
            return result
        
        wrapper.cache = cache_instance
        return wrapper
    
    return decorator

class ScanResultsCache:
    def __init__(self, cache_dir: Path | str):
        self.file_cache = FileCache(cache_dir, default_ttl=86400)
    
    def get_scan_result(self, url: str, mode: str, standards: list[str]) -> Optional[Dict[str, Any]]:
        cache_key = self._make_key(url, mode, standards)
        return self.file_cache.get(cache_key)
    
    def set_scan_result(
        self,
        url: str,
        mode: str,
        standards: list[str],
        result: Dict[str, Any],
        ttl: int = 86400,
    ) -> None:
        cache_key = self._make_key(url, mode, standards)
        self.file_cache.set(cache_key, result, ttl)
    
    def _make_key(self, url: str, mode: str, standards: list[str]) -> str:
        key_data = {
            "url": url,
            "mode": mode,
            "standards": sorted(standards),
        }
        return json.dumps(key_data, sort_keys=True)
