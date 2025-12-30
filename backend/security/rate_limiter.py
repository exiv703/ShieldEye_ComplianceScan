from __future__ import annotations

import time
from collections import deque
from threading import Lock
from typing import Dict, Optional

from ..core.exceptions import RateLimitError
from ..utils.logging_config import get_logger

logger = get_logger("rate_limiter")

class RateLimiter:
    
    def __init__(
        self,
        requests_per_second: float = 5.0,
        burst_size: Optional[int] = None,
    ):
        self.rate = requests_per_second
        self.burst_size = burst_size or int(requests_per_second * 2)
        self.tokens = float(self.burst_size)
        self.last_update = time.time()
        self.lock = Lock()
    
    def acquire(self, tokens: int = 1, blocking: bool = True, timeout: Optional[float] = None) -> bool:

        start_time = time.time()
        max_timeout = min(timeout, 300.0) if timeout is not None else 300.0
        
        while True:
            if time.time() - start_time > max_timeout:
                logger.warning(f"Rate limiter acquire timed out after {max_timeout}s")
                return False
            
            with self.lock:
                now = time.time()
                elapsed = now - self.last_update
                self.tokens = min(
                    self.burst_size,
                    self.tokens + elapsed * self.rate
                )
                self.last_update = now
                
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return True
                
                if not blocking:
                    wait_time = (tokens - self.tokens) / self.rate
                    raise RateLimitError(
                        f"Rate limit exceeded. Try again in {wait_time:.2f} seconds",
                        retry_after=int(wait_time) + 1
                    )
                
                if timeout and (time.time() - start_time) >= timeout:
                    return False
            
            time.sleep(0.1)
    
    def reset(self) -> None:
        with self.lock:
            self.tokens = float(self.burst_size)
            self.last_update = time.time()

class SlidingWindowRateLimiter:
    
    def __init__(self, max_requests: int, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: deque = deque()
        self.lock = Lock()
    
    def is_allowed(self, identifier: str = "default") -> bool:

        with self.lock:
            now = time.time()
            cutoff = now - self.window_seconds
            
            while self.requests and self.requests[0] < cutoff:
                self.requests.popleft()
            
            if len(self.requests) < self.max_requests:
                self.requests.append(now)
                return True
            
            return False
    
    def get_retry_after(self) -> int:
        with self.lock:
            if not self.requests:
                return 0
            
            oldest = self.requests[0]
            wait_time = self.window_seconds - (time.time() - oldest)
            return max(0, int(wait_time) + 1)

class MultiTierRateLimiter:
    
    def __init__(
        self,
        requests_per_second: float = 5.0,
        requests_per_minute: int = 100,
    ):
        self.second_limiter = RateLimiter(requests_per_second)
        self.minute_limiter = SlidingWindowRateLimiter(requests_per_minute, 60)
        self.lock = Lock()
    
    def acquire(self, blocking: bool = True, timeout: Optional[float] = None) -> bool:

        if not self.minute_limiter.is_allowed():
            if not blocking:
                retry_after = self.minute_limiter.get_retry_after()
                raise RateLimitError(
                    f"Per-minute rate limit exceeded. Try again in {retry_after} seconds",
                    retry_after=retry_after
                )
            return False
        
        return self.second_limiter.acquire(blocking=blocking, timeout=timeout)

class DomainRateLimiter:
    
    def __init__(self, requests_per_second: float = 5.0):
        self.rate = requests_per_second
        self.limiters: Dict[str, RateLimiter] = {}
        self.lock = Lock()
    
    def get_limiter(self, domain: str) -> RateLimiter:
        with self.lock:
            if domain not in self.limiters:
                self.limiters[domain] = RateLimiter(self.rate)
            return self.limiters[domain]
    
    def acquire(self, domain: str, blocking: bool = True, timeout: Optional[float] = None) -> bool:
        limiter = self.get_limiter(domain)
        return limiter.acquire(blocking=blocking, timeout=timeout)
    
    def cleanup_old_limiters(self, max_age_seconds: int = 3600) -> None:
        with self.lock:
            now = time.time()
            to_remove = [
                domain for domain, limiter in self.limiters.items()
                if now - limiter.last_update > max_age_seconds
            ]
            for domain in to_remove:
                del self.limiters[domain]
                logger.debug(f"Removed rate limiter for domain: {domain}")
