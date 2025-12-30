
from __future__ import annotations

import time
import json
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Callable
import requests
from datetime import datetime

@dataclass
class LoadTestResult:

    test_name: str
    total_requests: int
    successful_requests: int
    failed_requests: int
    total_duration: float
    min_response_time: float
    max_response_time: float
    avg_response_time: float
    median_response_time: float
    p95_response_time: float
    p99_response_time: float
    requests_per_second: float
    errors: List[str]
    timestamp: str

class LoadTester:

    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.session = requests.Session()
    
    def run_load_test(
        self,
        test_name: str,
        test_func: Callable,
        num_requests: int = 100,
        concurrent_users: int = 10,
        timeout: int = 30
    ) -> LoadTestResult:

        response_times: List[float] = []
        errors: List[str] = []
        successful = 0
        failed = 0
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=concurrent_users) as executor:
            futures = [
                executor.submit(self._execute_request, test_func, timeout)
                for _ in range(num_requests)
            ]
            
            for future in as_completed(futures):
                try:
                    duration, error = future.result()
                    if error:
                        failed += 1
                        errors.append(error)
                    else:
                        successful += 1
                        response_times.append(duration)
                except Exception as e:
                    failed += 1
                    errors.append(str(e))
        
        total_duration = time.time() - start_time
        
        if response_times:
            sorted_times = sorted(response_times)
            min_time = min(response_times)
            max_time = max(response_times)
            avg_time = statistics.mean(response_times)
            median_time = statistics.median(response_times)
            p95_time = sorted_times[int(len(sorted_times) * 0.95)]
            p99_time = sorted_times[int(len(sorted_times) * 0.99)]
        else:
            min_time = max_time = avg_time = median_time = p95_time = p99_time = 0.0
        
        rps = num_requests / total_duration if total_duration > 0 else 0
        
        return LoadTestResult(
            test_name=test_name,
            total_requests=num_requests,
            successful_requests=successful,
            failed_requests=failed,
            total_duration=total_duration,
            min_response_time=min_time,
            max_response_time=max_time,
            avg_response_time=avg_time,
            median_response_time=median_time,
            p95_response_time=p95_time,
            p99_response_time=p99_time,
            requests_per_second=rps,
            errors=errors[:10],
            timestamp=datetime.utcnow().isoformat()
        )
    
    def _execute_request(
        self,
        test_func: Callable,
        timeout: int
    ) -> tuple[float, str | None]:

        start = time.time()
        try:
            test_func()
            duration = time.time() - start
            return duration, None
        except Exception as e:
            duration = time.time() - start
            return duration, str(e)
    
    
    def test_health_check(self):

        response = self.session.get(f"{self.base_url}/health", timeout=5)
        response.raise_for_status()
    
    def test_list_scans(self):

        response = self.session.get(
            f"{self.base_url}/scans",
            params={"limit": 10},
            timeout=10
        )
        response.raise_for_status()
    
    def test_get_templates(self):

        response = self.session.get(f"{self.base_url}/templates", timeout=10)
        response.raise_for_status()
    
    def test_stats_endpoint(self):

        response = self.session.get(f"{self.base_url}/stats", timeout=10)
        response.raise_for_status()

def run_all_load_tests(base_url: str = "http://localhost:8000") -> Dict[str, Any]:

    tester = LoadTester(base_url)
    results = {}
    
    print("🚀 Starting Load Tests...")
    print(f"Target: {base_url}")
    print("-" * 80)
    
    print("\n📊 Test 1: Health Check (High Load)")
    result = tester.run_load_test(
        test_name="health_check_high_load",
        test_func=tester.test_health_check,
        num_requests=1000,
        concurrent_users=50,
        timeout=5
    )
    results["health_check_high_load"] = asdict(result)
    print_result_summary(result)
    
    print("\n📊 Test 2: List Scans (Moderate Load)")
    result = tester.run_load_test(
        test_name="list_scans_moderate",
        test_func=tester.test_list_scans,
        num_requests=200,
        concurrent_users=20,
        timeout=10
    )
    results["list_scans_moderate"] = asdict(result)
    print_result_summary(result)
    
    print("\n📊 Test 3: Get Templates (Light Load)")
    result = tester.run_load_test(
        test_name="get_templates_light",
        test_func=tester.test_get_templates,
        num_requests=100,
        concurrent_users=10,
        timeout=10
    )
    results["get_templates_light"] = asdict(result)
    print_result_summary(result)
    
    print("\n📊 Test 4: Stats Endpoint (Sustained Load)")
    result = tester.run_load_test(
        test_name="stats_sustained",
        test_func=tester.test_stats_endpoint,
        num_requests=500,
        concurrent_users=25,
        timeout=10
    )
    results["stats_sustained"] = asdict(result)
    print_result_summary(result)
    
    print("\n📊 Test 5: Spike Test (Sudden High Load)")
    result = tester.run_load_test(
        test_name="spike_test",
        test_func=tester.test_health_check,
        num_requests=500,
        concurrent_users=100,
        timeout=5
    )
    results["spike_test"] = asdict(result)
    print_result_summary(result)
    
    print("\n" + "=" * 80)
    print("📈 OVERALL LOAD TEST SUMMARY")
    print("=" * 80)
    
    total_requests = sum(r["total_requests"] for r in results.values())
    total_successful = sum(r["successful_requests"] for r in results.values())
    total_failed = sum(r["failed_requests"] for r in results.values())
    avg_rps = statistics.mean(r["requests_per_second"] for r in results.values())
    
    print(f"Total Requests:     {total_requests}")
    print(f"Successful:         {total_successful} ({total_successful/total_requests*100:.1f}%)")
    print(f"Failed:             {total_failed} ({total_failed/total_requests*100:.1f}%)")
    print(f"Average RPS:        {avg_rps:.2f}")
    
    success_rate = total_successful / total_requests * 100
    if success_rate >= 99.5:
        status = "✅ EXCELLENT"
    elif success_rate >= 95:
        status = "✓ GOOD"
    elif success_rate >= 90:
        status = "⚠ ACCEPTABLE"
    else:
        status = "❌ NEEDS IMPROVEMENT"
    
    print(f"\nPerformance Status: {status}")
    print("=" * 80)
    
    output_file = "load_test_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n💾 Results saved to: {output_file}")
    
    return results

def print_result_summary(result: LoadTestResult):

    success_rate = result.successful_requests / result.total_requests * 100
    
    print(f"  Total Requests:    {result.total_requests}")
    print(f"  Successful:        {result.successful_requests} ({success_rate:.1f}%)")
    print(f"  Failed:            {result.failed_requests}")
    print(f"  Duration:          {result.total_duration:.2f}s")
    print(f"  Requests/sec:      {result.requests_per_second:.2f}")
    print(f"  Avg Response:      {result.avg_response_time*1000:.2f}ms")
    print(f"  Median Response:   {result.median_response_time*1000:.2f}ms")
    print(f"  P95 Response:      {result.p95_response_time*1000:.2f}ms")
    print(f"  P99 Response:      {result.p99_response_time*1000:.2f}ms")
    
    if result.errors:
        print(f"  Errors (sample):   {result.errors[0]}")

if __name__ == "__main__":
    import sys
    
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    
    try:
        run_all_load_tests(base_url)
    except KeyboardInterrupt:
        print("\n\n⚠️  Load test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Load test failed: {e}")
        sys.exit(1)
