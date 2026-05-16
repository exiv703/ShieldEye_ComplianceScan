from __future__ import annotations

import asyncio
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict

from backend.utils.config import get_config
from backend.utils.logging_config import get_logger

logger = get_logger("observability")

try:
    from prometheus_client import Counter, Histogram, CollectorRegistry  # type: ignore[import-not-found]

    _PROMETHEUS_AVAILABLE = True
except ImportError:
    _PROMETHEUS_AVAILABLE = False

try:
    from opentelemetry import trace  # type: ignore[import-not-found]
    from opentelemetry.trace import SpanKind  # type: ignore[import-not-found]

    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False


class MetricsCollector:
    def __init__(self, registry: Any | None = None):
        self._lock = asyncio.Lock()
        self._use_prometheus = _PROMETHEUS_AVAILABLE and registry is not None
        self._registry = registry
        self._counters: Dict[str, Any] = {}
        self._histograms: Dict[str, Any] = {}
        self._dict_counters: Dict[str, int] = {}
        self._dict_histograms: Dict[str, list[float]] = {}

    async def inc_execution(self, standard: str, status: str) -> None:
        if self._use_prometheus:
            name = "benchmark_executions_total"
            if name not in self._counters:
                self._counters[name] = Counter(
                    name,
                    "Total benchmark executions",
                    ["standard", "status"],
                    registry=self._registry,
                )
            self._counters[name].labels(standard=standard, status=status).inc()
        else:
            key = f"execution:{standard}:{status}"
            async with self._lock:
                self._dict_counters[key] = self._dict_counters.get(key, 0) + 1

    async def inc_rate_limit_hit(self) -> None:
        if self._use_prometheus:
            name = "rate_limit_hits_total"
            if name not in self._counters:
                self._counters[name] = Counter(
                    name, "Total rate limit hits", registry=self._registry
                )
            self._counters[name].inc()
        else:
            async with self._lock:
                self._dict_counters["rate_limit_hits"] = (
                    self._dict_counters.get("rate_limit_hits", 0) + 1
                )

    async def inc_circuit_breaker_trip(self) -> None:
        if self._use_prometheus:
            name = "circuit_breaker_trips_total"
            if name not in self._counters:
                self._counters[name] = Counter(
                    name, "Total circuit breaker trips", registry=self._registry
                )
            self._counters[name].inc()
        else:
            async with self._lock:
                self._dict_counters["circuit_breaker_trips"] = (
                    self._dict_counters.get("circuit_breaker_trips", 0) + 1
                )

    async def observe_duration(self, operation: str, duration_ms: float) -> None:
        if self._use_prometheus:
            name = "operation_duration_milliseconds"
            if name not in self._histograms:
                self._histograms[name] = Histogram(
                    name,
                    "Operation duration in milliseconds",
                    ["operation"],
                    registry=self._registry,
                )
            self._histograms[name].labels(operation=operation).observe(duration_ms)
        else:
            key = f"duration:{operation}"
            async with self._lock:
                if key not in self._dict_histograms:
                    self._dict_histograms[key] = []
                self._dict_histograms[key].append(duration_ms)

    async def export(self) -> None:
        if self._use_prometheus:
            counter_count = len(self._counters)
            histogram_count = len(self._histograms)
        else:
            async with self._lock:
                counter_count = len(self._dict_counters)
                histogram_count = len(self._dict_histograms)
        logger.debug(
            "Metrics exported: %d counters, %d histograms",
            counter_count,
            histogram_count,
        )


@asynccontextmanager
async def trace_span(
    name: str, kind: str = "internal", **attrs: Any
) -> AsyncIterator[Dict[str, Any]]:
    if _OTEL_AVAILABLE:
        tracer = trace.get_tracer("shieldeye")
        otel_kind = SpanKind.INTERNAL
        try:
            otel_kind = SpanKind[kind.upper()]
        except KeyError:
            pass
        with tracer.start_as_current_span(name, kind=otel_kind) as span:
            for key, value in attrs.items():
                span.set_attribute(key, value)
            trace_id = format(span.get_span_context().trace_id, "032x")
            logger.info("Trace span started: %s (trace_id=%s)", name, trace_id)
            yield {"trace_id": trace_id}
    else:
        mock_trace_id = f"mock-{uuid.uuid4().hex[:12]}"
        logger.info("Trace span started: %s (trace_id=%s)", name, mock_trace_id)
        yield {"trace_id": mock_trace_id}


def get_observability_config() -> Dict[str, bool]:
    config = get_config()
    return {
        "enable_prometheus_export": getattr(config, "enable_prometheus_export", False),
        "enable_opentelemetry": getattr(config, "enable_opentelemetry", False),
    }
