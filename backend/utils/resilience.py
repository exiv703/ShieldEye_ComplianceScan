from __future__ import annotations

import asyncio
import inspect
import time
from enum import Enum
from typing import Any, Callable

import redis.asyncio as redis

from backend.utils.config import get_config
from backend.utils.logging_config import get_logger

logger = get_logger("resilience")


class RateLimitError(Exception):
    """Raised when a rate limit threshold is exceeded."""


class CircuitState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class RateLimiter:
    def __init__(
        self,
        redis_client: redis.Redis | None,
        max_requests: int = 10,
        window_seconds: int = 60,
    ):
        self.redis = redis_client
        self.max_requests = max_requests
        self.window_seconds = window_seconds

    async def allow_request(self, key: str) -> bool:
        if self.redis is None:
            return True
        count = await self.redis.incr(key)
        if count == 1:
            await self.redis.expire(key, self.window_seconds)
        if count > self.max_requests:
            logger.warning("Rate limit hit for %s", key)
            return False
        return True

    async def get_remaining(self, key: str) -> int:
        if self.redis is None:
            return self.max_requests
        count = await self.redis.get(key)
        if count is None:
            return self.max_requests
        return max(0, self.max_requests - int(count))


class CircuitBreaker:
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 300,
        service_name: str = "unknown",
        on_open: Callable[[str], Any] | None = None,
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.service_name = service_name
        self.on_open = on_open
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time = 0.0
        self._lock = asyncio.Lock()

    async def execute(
        self, func: Callable[..., Any] | Any, *args: Any, **kwargs: Any
    ) -> Any:
        async with self._lock:
            if self.state == CircuitState.OPEN:
                if time.monotonic() - self.last_failure_time >= self.recovery_timeout:
                    self.state = CircuitState.HALF_OPEN
                    self.failure_count = 0
                else:
                    logger.info("Circuit breaker OPEN for %s", self.service_name)
                    raise Exception(f"Circuit breaker OPEN for {self.service_name}")

        try:
            if inspect.isawaitable(func):
                result = await func
            elif inspect.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
        except Exception:
            async with self._lock:
                self.failure_count += 1
                self.last_failure_time = time.monotonic()
                if self.failure_count >= self.failure_threshold:
                    if self.state != CircuitState.OPEN:
                        self.state = CircuitState.OPEN
                        if self.on_open:
                            asyncio.create_task(self._invoke_on_open())
            raise

        async with self._lock:
            if self.state == CircuitState.HALF_OPEN:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
            elif self.state == CircuitState.CLOSED and self.failure_count > 0:
                self.failure_count = 0

        return result

    async def _invoke_on_open(self) -> None:
        if self.on_open:
            try:
                await self.on_open(self.service_name)
            except Exception:
                pass


_redis_client: redis.Redis | None = None


async def get_redis_client() -> redis.Redis | None:
    global _redis_client
    if _redis_client is None:
        config = get_config()
        if config.redis_url is not None:
            _redis_client = redis.from_url(str(config.redis_url), decode_responses=True)
    return _redis_client


_CIRCUIT_BREAKERS: dict[str, CircuitBreaker] = {}


def get_circuit_breaker(
    service_name: str,
    failure_threshold: int = 5,
    recovery_timeout: int = 300,
    on_open: Callable[[str], Any] | None = None,
) -> CircuitBreaker:
    if service_name not in _CIRCUIT_BREAKERS:
        _CIRCUIT_BREAKERS[service_name] = CircuitBreaker(
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
            service_name=service_name,
            on_open=on_open,
        )
    return _CIRCUIT_BREAKERS[service_name]
