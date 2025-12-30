
from __future__ import annotations

import pytest
import time
from backend.core.scanner import Scanner
from backend.storage.database import ScanDatabase
from backend.storage.cache import Cache
from backend.security.rate_limiter import RateLimiter, DomainRateLimiter
import tempfile
from pathlib import Path

class TestScannerPerformance:

    def test_scanner_initialization_time(self):

        start = time.time()
        scanner = Scanner(
            "https://example.com",
            ["GDPR"],
            "Quick/Safe",
            enable_metrics=False
        )
        duration = time.time() - start
        
        assert duration < 0.1, f"Scanner initialization took {duration:.3f}s (should be < 0.1s)"
    
    def test_rate_limiter_overhead(self):

        limiter = RateLimiter(requests_per_second=100.0)
        
        start = time.time()
        for _ in range(100):
            limiter.acquire()
        duration = time.time() - start
        
        assert duration < 2.0, f"Rate limiter took {duration:.3f}s for 100 requests"
    
    def test_domain_rate_limiter_performance(self):

        limiter = DomainRateLimiter(requests_per_second=50.0)
        
        domains = [f"domain{i}.com" for i in range(10)]
        
        start = time.time()
        for domain in domains:
            for _ in range(10):
                limiter.acquire(domain)
        duration = time.time() - start
        
        assert duration < 3.0, f"Domain rate limiter took {duration:.3f}s"

class TestDatabasePerformance:

    @pytest.fixture
    def temp_db(self):

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        
        db = ScanDatabase(db_path)
        yield db
        
        Path(db_path).unlink(missing_ok=True)
    
    def test_bulk_insert_performance(self, temp_db):

        start = time.time()
        
        for i in range(100):
            temp_db.create_scan(
                scan_id=f"scan_{i}",
                url=f"https://example{i}.com",
                mode="Quick/Safe",
                standards=["GDPR"]
            )
        
        duration = time.time() - start
        
        assert duration < 1.0, f"Bulk insert took {duration:.3f}s (should be < 1s)"
    
    def test_query_performance(self, temp_db):

        for i in range(100):
            temp_db.create_scan(
                scan_id=f"scan_{i}",
                url=f"https://example{i}.com",
                mode="Quick/Safe",
                standards=["GDPR"]
            )
        
        start = time.time()
        scans = temp_db.get_scans(limit=50)
        duration = time.time() - start
        
        assert len(scans) == 50
        assert duration < 0.1, f"Query took {duration:.3f}s (should be < 0.1s)"
    
    def test_statistics_performance(self, temp_db):

        for i in range(100):
            temp_db.create_scan(
                scan_id=f"scan_{i}",
                url=f"https://example{i}.com",
                mode="Quick/Safe",
                standards=["GDPR"]
            )
        
        start = time.time()
        stats = temp_db.get_statistics()
        duration = time.time() - start
        
        assert stats["total_scans"] == 100
        assert duration < 0.2, f"Statistics took {duration:.3f}s (should be < 0.2s)"

class TestCachePerformance:

    def test_cache_hit_performance(self):

        cache = Cache(default_ttl=60)
        
        for i in range(100):
            cache.set(f"key_{i}", f"value_{i}")
        
        start = time.time()
        for i in range(100):
            value = cache.get(f"key_{i}")
            assert value == f"value_{i}"
        duration = time.time() - start
        
        assert duration < 0.01, f"100 cache hits took {duration:.3f}s (should be < 0.01s)"
    
    def test_cache_miss_performance(self):

        cache = Cache(default_ttl=60)
        
        start = time.time()
        for i in range(100):
            value = cache.get(f"nonexistent_{i}")
            assert value is None
        duration = time.time() - start
        
        assert duration < 0.01, f"100 cache misses took {duration:.3f}s"
    
    def test_cache_eviction_performance(self):

        cache = Cache(default_ttl=60)
        
        start = time.time()
        for i in range(200):
            cache.set(f"key_{i}", f"value_{i}")
        duration = time.time() - start
        
        assert duration < 0.1, f"Cache operations took {duration:.3f}s"
        assert cache.size() == 200

class TestMemoryUsage:

    def test_scanner_memory_footprint(self):

        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        mem_before = process.memory_info().rss / 1024 / 1024
        
        scanners = []
        for i in range(10):
            scanner = Scanner(
                f"https://example{i}.com",
                ["GDPR"],
                "Quick/Safe",
                enable_metrics=False
            )
            scanners.append(scanner)
        
        mem_after = process.memory_info().rss / 1024 / 1024
        mem_increase = mem_after - mem_before
        
        assert mem_increase < 50, f"10 scanners used {mem_increase:.2f}MB (should be < 50MB)"
    
    def test_cache_memory_limit(self):

        cache = Cache(default_ttl=60)
        
        large_data = "x" * 1000
        for i in range(1000):
            cache.set(f"key_{i}", large_data)
        
        assert cache.size() == 1000

class TestConcurrency:

    def test_concurrent_rate_limiter(self):

        from concurrent.futures import ThreadPoolExecutor
        
        limiter = RateLimiter(requests_per_second=100.0)
        
        def acquire_token():
            limiter.acquire()
            return True
        
        start = time.time()
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(acquire_token) for _ in range(100)]
            results = [f.result() for f in futures]
        duration = time.time() - start
        
        assert all(results)
        assert duration < 3.0, f"Concurrent rate limiting took {duration:.3f}s"
    
    def test_concurrent_cache_access(self):

        from concurrent.futures import ThreadPoolExecutor
        
        cache = Cache(default_ttl=60)
        
        def cache_operation(i):
            cache.set(f"key_{i}", f"value_{i}")
            value = cache.get(f"key_{i}")
            return value == f"value_{i}"
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(cache_operation, i) for i in range(100)]
            results = [f.result() for f in futures]
        
        assert all(results)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
