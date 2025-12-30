
from __future__ import annotations

from locust import HttpUser, task, between, events
import random
import json

class ShieldEyeUser(HttpUser):

    wait_time = between(1, 5)
    
    def on_start(self):

        pass
    
    @task(10)
    def health_check(self):

        self.client.get("/health")
    
    @task(5)
    def list_scans(self):

        params = {
            "limit": random.randint(5, 20),
            "offset": random.randint(0, 10)
        }
        self.client.get("/scans", params=params)
    
    @task(3)
    def get_templates(self):

        self.client.get("/templates")
    
    @task(2)
    def get_specific_template(self):

        templates = [
            "quick_gdpr",
            "full_gdpr",
            "pci_dss_ecommerce",
            "iso_27001_security",
            "security_headers"
        ]
        template = random.choice(templates)
        self.client.get(f"/templates/{template}")
    
    @task(2)
    def get_stats(self):

        self.client.get("/stats")
    
    @task(1)
    def list_schedules(self):

        self.client.get("/schedules")
    
    @task(1)
    def list_webhooks(self):

        self.client.get("/webhooks")

class AdminUser(HttpUser):

    wait_time = between(2, 10)
    
    @task(5)
    def health_check(self):

        self.client.get("/health")
    
    @task(3)
    def list_all_scans(self):

        self.client.get("/scans", params={"limit": 100})
    
    @task(2)
    def get_stats(self):

        self.client.get("/stats")
    
    @task(1)
    def create_scan(self):

        payload = {
            "url": "https://example.com",
            "standards": ["GDPR"],
            "mode": "Quick/Safe",
            "template": "quick_gdpr"
        }
        with self.client.post(
            "/scans",
            json=payload,
            catch_response=True
        ) as response:
            if response.status_code in [401, 403]:
                response.success()

class StressTestUser(HttpUser):

    wait_time = between(0.1, 0.5)
    
    @task
    def rapid_health_checks(self):

        self.client.get("/health")

@events.test_start.add_listener
def on_test_start(environment, **kwargs):

    print("🚀 Load test starting...")

@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):

    print("🏁 Load test completed!")
    
    stats = environment.stats
    print("\n" + "=" * 80)
    print("📊 LOAD TEST SUMMARY")
    print("=" * 80)
    print(f"Total Requests:     {stats.total.num_requests}")
    print(f"Failed Requests:    {stats.total.num_failures}")
    print(f"Success Rate:       {(1 - stats.total.fail_ratio) * 100:.2f}%")
    print(f"Avg Response Time:  {stats.total.avg_response_time:.2f}ms")
    print(f"Min Response Time:  {stats.total.min_response_time:.2f}ms")
    print(f"Max Response Time:  {stats.total.max_response_time:.2f}ms")
    print(f"Requests/sec:       {stats.total.total_rps:.2f}")
    print("=" * 80)

class QuickLoadTest(HttpUser):

    wait_time = between(1, 2)
    
    @task
    def quick_test(self):
        self.client.get("/health")
        self.client.get("/templates")

class SustainedLoadTest(HttpUser):

    wait_time = between(2, 5)
    
    @task(3)
    def read_operations(self):
        endpoints = ["/health", "/templates", "/stats"]
        endpoint = random.choice(endpoints)
        self.client.get(endpoint)
    
    @task(1)
    def list_operations(self):
        self.client.get("/scans", params={"limit": 10})

class SpikeTest(HttpUser):

    wait_time = between(0.1, 1)
    
    @task
    def burst_requests(self):
        for _ in range(random.randint(1, 5)):
            self.client.get("/health")
