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
from backend.utils.monitoring import get_metrics_collector
from benchmark.engine import ControlMapping

logger = get_logger("benchmark.orchestrator")

_BENCHMARK_SCAN_ID = "benchmark_orchestrator"

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
    """Pydantic v2 schema capturing the outcome of a single compliance check."""

    control_id: str
    target: str
    status: Literal["passed", "failed", "skipped", "error"]
    output: str
    duration_ms: int
    timestamp: datetime
    idempotency_hash: str


def _scrub_output(text: str) -> str:
    """Redact likely secrets from command output before persistence."""
    for pattern in _SECRET_REDACTION_PATTERNS:
        text = pattern.sub("***REDACTED***", text)
    return text


def _compute_idempotency_hash(control_id: str, target: str, window_minutes: int) -> str:
    """Compute a time-bucketed SHA-256 hash for idempotency deduplication."""
    now = datetime.now(timezone.utc)
    window_seconds = window_minutes * 60
    time_bucket = round(now.timestamp() / window_seconds)
    hash_input = f"{control_id}:{target}:{time_bucket}"
    return hashlib.sha256(hash_input.encode("utf-8")).hexdigest()


def is_execution_idempotent(
    control_id: str, target: str, window_minutes: int = 60
) -> bool:
    # Why 60min window? Balances audit freshness vs duplicate execution cost
    idempotency_hash = _compute_idempotency_hash(control_id, target, window_minutes)

    config = get_config()
    db = ScanDatabase(config.database.db_path)

    with db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT value FROM scan_metadata WHERE key = ?",
            (f"benchmark_idempotency_{idempotency_hash}",),
        )
        row = cursor.fetchone()
        if row is not None and row["value"] != "error":
            logger.info(
                "Idempotent replay: returning cached result for %s", idempotency_hash
            )
            return True
    return False


def _get_cached_result(idempotency_hash: str) -> BenchmarkResult | None:
    """Retrieve a cached BenchmarkResult from scan_metadata if available."""
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
    """Store a BenchmarkResult in scan_metadata for future idempotency checks."""
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
    """Execute a shell command asynchronously with timeout and graceful cancellation."""
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
    """Determine if an exception is likely transient and worth retrying."""
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


async def execute_benchmark(
    mapping: ControlMapping,
    target: str,
    timeout: int = 300,
) -> BenchmarkResult:
    """Execute a control mapping check against a target with idempotency, retry, and audit logging."""
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

    last_exception: Exception | None = None
    max_retries = 3
    # Why 3 retries? Covers transient network glitches without excessive delay
    for attempt in range(1, max_retries + 1):
        start_time = time.time()
        try:
            returncode, stdout, stderr = await _run_check_with_timeout(command, timeout)
            duration_ms = int((time.time() - start_time) * 1000)
            raw_output = stdout.strip() or stderr.strip()
            output = _scrub_output(raw_output)

            if re.search(mapping.expected_output, output, re.IGNORECASE):
                status: Literal["passed", "failed", "skipped", "error"] = "passed"
            else:
                status = "failed"
                logger.warning(
                    "Benchmark failed for %s on %s. hint: check target reachability or increase timeout",
                    control_id,
                    target,
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
                    }
                },
            )

            # Metrics hook (non-blocking)
            try:
                metrics = get_metrics_collector()
                if hasattr(metrics, "benchmark_executions"):
                    metrics.benchmark_executions.labels(
                        standard=mapping.standard, status=status
                    ).inc()
                else:
                    metrics.record_error(f"benchmark_{mapping.standard}_{status}")
            except Exception:
                pass

            _store_benchmark_result(result)
            return result

        except asyncio.TimeoutError as e:
            last_exception = e
            duration_ms = int((time.time() - start_time) * 1000)
            logger.warning(
                "Benchmark timeout for %s on %s (attempt %d/%d, %d ms)",
                control_id,
                target,
                attempt,
                max_retries,
                duration_ms,
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
        "Benchmark failed for %s on %s. hint: check target reachability or increase timeout",
        control_id,
        target,
    )

    _store_benchmark_result(result)
    return result


# Impact: Async-safe benchmark orchestration with idempotency guards, retry/backoff,
# structured operational logging, and metrics hooks provides deterministic, auditable
# compliance check execution without duplicate work or blocking I/O.
