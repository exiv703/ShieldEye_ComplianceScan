from __future__ import annotations

import pytest
import time
from backend.rate_limiter import RateLimiter, SlidingWindowRateLimiter
from backend.exceptions import RateLimitError

class TestRateLimiter:

    def test_acquire_within_limit(self):

        limiter = RateLimiter(requests_per_second=10.0)
        
        assert limiter.acquire(blocking=False) is True
        assert limiter.acquire(blocking=False) is True
    
    def test_acquire_exceeds_limit(self):

        limiter = RateLimiter(requests_per_second=1.0, burst_size=2)
        
        limiter.acquire(blocking=False)
        limiter.acquire(blocking=False)
        
        with pytest.raises(RateLimitError):
            limiter.acquire(blocking=False)
    
    def test_tokens_refill(self):

        limiter = RateLimiter(requests_per_second=10.0, burst_size=1)
        
        limiter.acquire(blocking=False)
        
        time.sleep(0.2)
        
        assert limiter.acquire(blocking=False) is True
    
    def test_reset(self):

        limiter = RateLimiter(requests_per_second=1.0, burst_size=1)
        
        limiter.acquire(blocking=False)
        
        limiter.reset()
        
        assert limiter.acquire(blocking=False) is True

class TestSlidingWindowRateLimiter:

    def test_within_limit(self):

        limiter = SlidingWindowRateLimiter(max_requests=5, window_seconds=1)
        
        for _ in range(5):
            assert limiter.is_allowed() is True
    
    def test_exceeds_limit(self):

        limiter = SlidingWindowRateLimiter(max_requests=2, window_seconds=1)
        
        assert limiter.is_allowed() is True
        assert limiter.is_allowed() is True
        assert limiter.is_allowed() is False
    
    def test_window_slides(self):

        limiter = SlidingWindowRateLimiter(max_requests=1, window_seconds=1)
        
        assert limiter.is_allowed() is True
        assert limiter.is_allowed() is False
        
        time.sleep(1.1)
        
        assert limiter.is_allowed() is True

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
