from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel

from backend.storage.database import ScanDatabase
from backend.utils.config import get_config
from backend.utils.logging_config import get_logger
from backend.utils.observability import MetricsCollector, trace_span
from benchmark.engine import ControlMapping
from backend.utils.resilience import (
    CircuitBreaker,
    RateLimitError,
    RateLimiter,
    get_circuit_breaker,
    get_redis_client,
)

logger = get_logger("benchmark.orchestrator")

_BENCHMARK_SCAN_ID = "benchmark_orchestrator"

_RATE_LIMITER: RateLimiter | None = None
_METRICS: dict[str, int] = {"rate_limit_hits": 0, "circuit_breaker_trips": 0}
_METRICS_LOCK = asyncio.Lock()
_METRICS_COLLECTOR: MetricsCollector = MetricsCollector()


async def _get_rate_limiter() -> RateLimiter:
    global _RATE_LIMITER
    if _RATE_LIMITER is None:
        redis_client = await get_redis_client()
        _RATE_LIMITER = RateLimiter(redis_client, max_requests=10, window_seconds=60)
    return _RATE_LIMITER


async def _on_circuit_open(service_name: str) -> None:
    async with _METRICS_LOCK:
        _METRICS["circuit_breaker_trips"] += 1
    await _METRICS_COLLECTOR.inc_circuit_breaker_trip()


_SECRET_REDACTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|bearer)\s*[:=]\s*\S+"
    ),
    re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
        r".*?"
        r"-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        re.DOTALL,
    ),
]


class BenchmarkResult(BaseModel):  # type: ignore[misc]
    """Normalized result persisted for each benchmark control execution."""

    control_id: str
    target: str
    status: Literal["passed", "failed", "skipped", "error"]
    output: str
    duration_ms: int
    timestamp: datetime
    idempotency_hash: str


def _scrub_output(text: str) -> str:
    for pattern in _SECRET_REDACTION_PATTERNS:
        text = pattern.sub("***REDACTED***", text)
    return text


def _compute_idempotency_hash(control_id: str, target: str, window_minutes: int) -> str:
    now = datetime.now(timezone.utc)
    window_seconds = window_minutes * 60
    time_bucket = round(now.timestamp() / window_seconds)
    hash_input = f"{control_id}:{target}:{time_bucket}"
    return hashlib.sha256(hash_input.encode("utf-8")).hexdigest()


def _get_scan_metadata_values(keys: list[str]) -> dict[str, str]:
    if not keys:
        return {}

    # Why batch queries? Reduces DB round-trips from O(N) to O(1) for idempotency checks
    config = get_config()
    db = ScanDatabase(config.database.db_path)
    placeholders = ", ".join("?" for _ in keys)

    with db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            f"SELECT key, value FROM scan_metadata WHERE key IN ({placeholders}) "
            "ORDER BY id DESC",
            keys,
        )
        rows = cursor.fetchall()

    latest_by_key: dict[str, str] = {}
    for row in rows:
        key = str(row["key"])
        if key not in latest_by_key:
            latest_by_key[key] = str(row["value"])
    return latest_by_key


def is_execution_idempotent(
    control_id: str, target: str, window_minutes: int = 60
) -> bool:
    idempotency_hash = _compute_idempotency_hash(control_id, target, window_minutes)
    metadata_key = f"benchmark_idempotency_{idempotency_hash}"

    metadata_values = _get_scan_metadata_values([metadata_key])
    value = metadata_values.get(metadata_key)
    if value is not None and value != "error":
        logger.info(
            "Idempotent replay: returning cached result for %s", idempotency_hash
        )
        return True

    config = get_config()
    db = ScanDatabase(config.database.db_path)

    with db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM scan_metadata WHERE key = ? AND value != ? LIMIT 1",
            (metadata_key, "error"),
        )
        row = cursor.fetchone()
        if row is not None:
            logger.info(
                "Idempotent replay: returning cached result for %s", idempotency_hash
            )
            return True
    return False


def _get_cached_result(idempotency_hash: str) -> BenchmarkResult | None:
    config = get_config()
    db = ScanDatabase(config.database.db_path)

    with db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT value FROM scan_metadata WHERE key = ? ORDER BY id DESC LIMIT 1",
            (f"benchmark_result_{idempotency_hash}",),
        )
        row = cursor.fetchone()
        if row:
            try:
                data = json.loads(row["value"])
                return BenchmarkResult(**data)
            except Exception:
                logger.warning(
                    "Failed to deserialize cached benchmark result for %s",
                    idempotency_hash,
                )
    return None


def _store_benchmark_result(result: BenchmarkResult) -> None:
    config = get_config()
    db = ScanDatabase(config.database.db_path)

    with db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scan_metadata (scan_id, key, value) VALUES (?, ?, ?)",
            (
                _BENCHMARK_SCAN_ID,
                f"benchmark_idempotency_{result.idempotency_hash}",
                result.status,
            ),
        )
        cursor.execute(
            "INSERT INTO scan_metadata (scan_id, key, value) VALUES (?, ?, ?)",
            (
                _BENCHMARK_SCAN_ID,
                f"benchmark_result_{result.idempotency_hash}",
                result.model_dump_json(),
            ),
        )


async def _run_check_with_timeout(command: str, timeout: int) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_shell(
        command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise
    return (
        proc.returncode or 0,
        stdout.decode("utf-8", errors="replace"),
        stderr.decode("utf-8", errors="replace"),
    )


def _is_transient_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    transient_patterns = [
        "timeout",
        "temporary failure",
        "connection reset",
        "connection refused",
        "network is unreachable",
        "no route to host",
        "dns",
        "temporary",
        "try again",
    ]
    return any(pattern in msg for pattern in transient_patterns)


def _failure_hint(control_id: str) -> str:
    if control_id == "CIS-4.1.3":
        return "hint: run 'sudo systemctl enable --now auditd' and verify 'systemctl is-active auditd' returns active"
    if control_id == "GDPR-32.1.1":
        return "hint: verify TLS certificate chain for target host and re-run openssl validation"
    if control_id.startswith("PCI-DSS-"):
        return "hint: verify TLS/password policy settings and confirm benchmark command output on target"
    return "hint: verify target reachability, command permissions, and expected output regex"


async def execute_benchmark(
    mapping: ControlMapping,
    target: str,
    timeout: int = 300,
) -> BenchmarkResult:
    """Execute one benchmark control with idempotency, retry, and audit traces."""
    control_id = mapping.control_id
    idempotency_hash = _compute_idempotency_hash(control_id, target, 60)

    # Check idempotency first → return cached result if found
    if is_execution_idempotent(control_id, target, 60):
        cached = _get_cached_result(idempotency_hash)
        if cached is not None:
            logger.info(
                "Idempotent replay: returning cached result for %s", idempotency_hash
            )
            return cached

    async with trace_span(
        "execute_benchmark",
        kind="benchmark",
        control_id=mapping.control_id,
        target=target,
    ) as trace_ctx:
        trace_id = trace_ctx.get("trace_id")
        # For Core/SurfaceScan HTTP calls: inject trace_id into request headers if OTel available
        # headers = {"X-Trace-Id": trace_id} if trace_id else {}
        # session.get(url, headers=headers, ...)

        # Prepare command with target substitution
        command = mapping.check_command
        if "{url}" in command:
            command = command.replace("{url}", target)
        if "{host}" in command:
            from urllib.parse import urlparse

            host = urlparse(target).hostname or target
            command = command.replace("{host}", host)
        if "{domain}" in command:
            from urllib.parse import urlparse

            domain = urlparse(target).netloc or target
            command = command.replace("{domain}", domain)

        # Rate limit guard per target
        rate_limiter = await _get_rate_limiter()
        rate_limit_key = f"rate_limit:{target}"
        if not await rate_limiter.allow_request(rate_limit_key):
            async with _METRICS_LOCK:
                _METRICS["rate_limit_hits"] += 1
            await _METRICS_COLLECTOR.inc_rate_limit_hit()
            raise RateLimitError(f"Rate limit exceeded for {target}")

        # Circuit breaker for upstream API calls
        circuit_breaker = get_circuit_breaker(
            "core_api",
            failure_threshold=5,
            recovery_timeout=300,
            on_open=_on_circuit_open,
        )

        last_exception: Exception | None = None
        max_retries = 3
        for attempt in range(1, max_retries + 1):
            start_time = time.time()
            try:
                returncode, stdout, stderr = await circuit_breaker.execute(
                    _run_check_with_timeout, command, timeout
                )
                duration_ms = int((time.time() - start_time) * 1000)
                raw_output = stdout.strip() or stderr.strip()
                output = _scrub_output(raw_output)

                if re.search(mapping.expected_output, output, re.IGNORECASE):
                    status: Literal["passed", "failed", "skipped", "error"] = "passed"
                else:
                    status = "failed"
                    logger.warning(
                        "Benchmark failed for %s on %s. %s",
                        control_id,
                        target,
                        _failure_hint(control_id),
                    )

                result = BenchmarkResult(
                    control_id=control_id,
                    target=target,
                    status=status,
                    output=output,
                    duration_ms=duration_ms,
                    timestamp=datetime.now(timezone.utc),
                    idempotency_hash=idempotency_hash,
                )

                logger.info(
                    "Benchmark executed",
                    extra={
                        "extra_data": {
                            "control_id": control_id,
                            "target": target,
                            "status": status,
                            "duration_ms": duration_ms,
                        },
                        "trace_id": trace_id,
                    },
                )

                await _METRICS_COLLECTOR.inc_execution(mapping.standard, result.status)
                await _METRICS_COLLECTOR.observe_duration(
                    "benchmark_execution", duration_ms
                )

                _store_benchmark_result(result)
                return result

            except asyncio.TimeoutError as e:
                last_exception = e
                duration_ms = int((time.time() - start_time) * 1000)
                logger.warning(
                    "Benchmark timeout for %s on %s (attempt %d/%d, %d ms). %s",
                    control_id,
                    target,
                    attempt,
                    max_retries,
                    duration_ms,
                    _failure_hint(control_id),
                )
                if attempt < max_retries:
                    backoff = 2 ** (attempt - 1)
                    await asyncio.sleep(backoff)
                else:
                    break

            except Exception as e:
                last_exception = e
                if _is_transient_error(e) and attempt < max_retries:
                    backoff = 2 ** (attempt - 1)
                    logger.warning(
                        "Transient error for %s on %s (attempt %d/%d): %s. Retrying in %ds",
                        control_id,
                        target,
                        attempt,
                        max_retries,
                        e,
                        backoff,
                    )
                    await asyncio.sleep(backoff)
                else:
                    break

        # All retries exhausted or non-transient error
        error_output = str(last_exception) if last_exception else "Unknown error"
        result = BenchmarkResult(
            control_id=control_id,
            target=target,
            status="error",
            output=_scrub_output(error_output),
            duration_ms=0,
            timestamp=datetime.now(timezone.utc),
            idempotency_hash=idempotency_hash,
        )

        logger.warning(
            "Benchmark failed for %s on %s. %s",
            control_id,
            target,
            _failure_hint(control_id),
        )

        _store_benchmark_result(result)
        return result
