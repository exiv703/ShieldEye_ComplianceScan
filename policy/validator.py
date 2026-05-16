from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
from pathlib import Path
from typing import Any, Coroutine, Literal, TypeVar, cast

import yaml  # type: ignore[import-untyped]
from pydantic import BaseModel, model_validator

from backend.utils.resilience import get_redis_client

logger = logging.getLogger("shieldeye.policy")

_POLICY_CACHE_TTL_SECONDS = 3600
_POLICY_CACHE_PREFIX = "policy_document:"
_T = TypeVar("_T")


class PolicyDocument(BaseModel):  # type: ignore[misc]
    """Canonical policy document used by API validation and benchmark mapping."""

    control_id: str
    standard: Literal["CIS", "PCI-DSS", "SOC2", "GDPR"]
    description: str
    check: str
    remediation: str
    severity: Literal["critical", "high", "medium", "low"]
    timeout: int = 600

    @model_validator(mode="after")  # type: ignore[misc]
    def validate_control_id(self) -> "PolicyDocument":
        pattern = rf"^{re.escape(self.standard)}-\d+\.\d+(\.\d+)?$"
        if not re.match(pattern, self.control_id):
            raise ValueError(
                f"control_id '{self.control_id}' does not match expected pattern "
                f"{self.standard}-X.Y[.Z]"
            )
        return self


def _is_policy_cache_enabled() -> bool:
    return os.getenv("ENABLE_POLICY_CACHE", "false").lower() in {"1", "true", "yes"}


def _run_cache_awaitable(awaitable: Coroutine[Any, Any, _T]) -> _T | None:
    try:
        asyncio.get_running_loop()
        return None
    except RuntimeError:
        return asyncio.run(awaitable)


def _get_cached_policy(cache_key: str) -> PolicyDocument | None:
    redis_client = _run_cache_awaitable(get_redis_client())
    if redis_client is None:
        # MVP fallback: direct parse if cache unavailable
        return None

    try:
        cached_payload = _run_cache_awaitable(redis_client.get(cache_key))
    except Exception as exc:
        logger.warning("Policy cache read failed for %s: %s", cache_key, exc)
        return None

    if not isinstance(cached_payload, str):
        return None

    try:
        return cast(PolicyDocument, PolicyDocument.model_validate_json(cached_payload))
    except Exception:
        logger.warning("Policy cache contained invalid payload for %s", cache_key)
        return None


def _store_cached_policy(cache_key: str, policy_document: PolicyDocument) -> None:
    redis_client = _run_cache_awaitable(get_redis_client())
    if redis_client is None:
        return

    try:
        _run_cache_awaitable(
            redis_client.set(
                cache_key,
                policy_document.model_dump_json(),
                ex=_POLICY_CACHE_TTL_SECONDS,
            )
        )
    except Exception as exc:
        logger.warning("Policy cache write failed for %s: %s", cache_key, exc)


def load_policy_yaml(path: str) -> PolicyDocument:
    file_path = Path(path)
    try:
        content = file_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise FileNotFoundError(f"Policy file not found: {path}") from None

    cache_key = ""
    if _is_policy_cache_enabled():
        # Why optional? Policy cache adds Redis dependency; filesystem parse is safe fallback
        cache_key = f"{_POLICY_CACHE_PREFIX}{hashlib.sha256(content.encode('utf-8')).hexdigest()}"
        cached_policy = _get_cached_policy(cache_key)
        if cached_policy is not None:
            return cached_policy

    data: Any = yaml.safe_load(content)

    if not isinstance(data, dict):
        raise ValueError(f"Expected YAML mapping at root, got {type(data).__name__}")

    policy_document = PolicyDocument(**data)
    if cache_key:
        _store_cached_policy(cache_key, policy_document)

    return policy_document


def validate_rego_stub(content: str) -> bool:
    has_package = "package" in content
    has_rule_or_default = "rule" in content or "default" in content
    has_allow = "allow" in content

    is_valid = has_package and has_rule_or_default and has_allow

    if not is_valid:
        missing = []
        if not has_package:
            missing.append("'package'")
        if not has_rule_or_default:
            missing.append("'rule' or 'default'")
        if not has_allow:
            missing.append("'allow'")
        logger.warning(
            "Rego stub appears incomplete: missing %s",
            ", ".join(missing),
        )

    return is_valid
