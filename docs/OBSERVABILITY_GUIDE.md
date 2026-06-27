# Observability Guide

This guide covers the observability and resilience controls: metrics, health checks, rate limiting and circuit breakers.

---

## Metrics Export

ShieldEye uses `MetricsCollector` (`backend/utils/observability.py`) to track key counters and operation latency.

### Enable Prometheus Export

Set the Phase 3 observability flag in `.env`:

```bash
SHIELDEYE_ENABLE_PROMETHEUS_EXPORT=true
```

When enabled, `MetricsCollector` emits counters/histograms compatible with Prometheus client instrumentation.

### Recommended Endpoint

Expose a metrics endpoint from your service deployment (commonly `/metrics` on the API container).

```yaml
# docker-compose excerpt (example)
services:
  compliancescan-api:
    ports:
      - "8000:8000"
    environment:
      SHIELDEYE_ENABLE_PROMETHEUS_EXPORT: "true"
```

### Sample Prometheus Scrape Config

```yaml
scrape_configs:
  - job_name: "shieldeye-compliancescan"
    scrape_interval: 15s
    metrics_path: /metrics
    static_configs:
      - targets:
          - "compliancescan-api:8000"
```

---

## Tracing

ShieldEye uses `trace_span(...)` (`backend/utils/observability.py`) as the tracing abstraction. It supports OpenTelemetry when installed and degrades safely to generated mock trace IDs.

### Enable OpenTelemetry

```bash
SHIELDEYE_ENABLE_OPENTELEMETRY=true
```

### Usage Pattern

```python
from backend.utils.observability import trace_span

async with trace_span("scan.orchestrate", kind="server", scan_id=scan_id) as span_ctx:
    trace_id = span_ctx["trace_id"]
    # Include trace_id in logs and downstream metadata
```

### `trace_id` Propagation to Core / SurfaceScan

Use the `trace_id` value from `trace_span` and propagate it in:

- Structured logs for cross-service correlation
- Outbound request headers to ShieldEye-Core and ShieldEye-SurfaceScan
- Any queued job metadata used by async orchestration

Recommended header convention:

```http
X-Trace-Id: <trace_id>
```

---

## Resilience Tuning

Phase 3 resilience controls are implemented in `backend/utils/resilience.py`.

### Rate Limit Window

`RateLimiter(max_requests=10, window_seconds=60)` defaults to 10 requests per 60 seconds per key.

Adjustment guidance:

- Increase `max_requests` for trusted internal workloads with stable upstream latency.
- Increase `window_seconds` to smooth bursty clients while preserving backend stability.
- Keep Redis healthy (`SHIELDEYE_REDIS_URL`) to avoid blind spots in distributed rate limiting.

### Circuit Breaker Thresholds

`CircuitBreaker(failure_threshold=5, recovery_timeout=300)` defaults to open after 5 failures and retry after 300 seconds.

Adjustment guidance:

- Lower `failure_threshold` for highly fragile or rate-limited upstream dependencies.
- Raise `failure_threshold` if transient failures are common but brief.
- Lower `recovery_timeout` for fast-recovering services; raise it for unstable dependencies to reduce flapping.

---

## Correlation Backend

Phase 3 introduces `CorrelationEngine` (`integrations/correlation.py`) with two backends:

- `heuristic`: deterministic category/prefix mapping
- `ml`: semantic similarity using sentence embeddings

### Backend Selection

```bash
ENABLE_ML_CORRELATION=false
```

- `false` → heuristic backend only
- `true` → ML backend preferred with automatic heuristic fallback

### Confidence Threshold Tuning

```bash
ML_CORRELATION_CONFIDENCE_THRESHOLD=0.75
```

`confidence_threshold` is used by `CorrelationEngine` to decide whether ML confidence is strong enough to accept.

Adjustment guidance:

- Raise threshold (for example `0.80`–`0.90`) to reduce false positives.
- Lower threshold (for example `0.60`–`0.70`) to increase recall when mappings are sparse.
- Validate threshold changes using representative findings/control descriptions before production rollout.

### Fallback Behavior

If ML is disabled, unavailable, or below `confidence_threshold`, `CorrelationEngine` falls back to heuristic matching and returns method metadata (`"method": "heuristic"`) with reason context.

# Impact: Observability and resilience runbooks make Phase 3 controls operable, measurable, and audit-ready for v0.3.0-rc1 production rollout.
