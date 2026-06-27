from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Literal, cast
from urllib import request as urllib_request

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
import redis.asyncio as redis

from backend.security.auth import AuthenticationError, get_auth_manager
from backend.utils.config import get_config
from backend.utils.resilience import get_circuit_breaker, get_redis_client

logger = logging.getLogger("shieldeye.api.monitoring")
monitoring_router = APIRouter(tags=["monitoring"])


class AlertRule(BaseModel):  # type: ignore[misc]
    rule_id: str = Field(..., description="UUID identifier")
    name: str = Field(..., min_length=1)
    condition: Literal[
        "control_failed", "scan_timeout", "rate_limit_hit", "circuit_breaker_open"
    ]
    threshold: int = Field(..., ge=1)
    window_seconds: int = Field(..., ge=1)
    # webhook/slack only - email would need SMTP wiring we don't have yet
    notification_channels: list[Literal["webhook", "slack"]]
    enabled: bool = True


class AlertEvaluator:
    def __init__(self) -> None:
        self._events_by_rule: dict[str, list[datetime]] = {}

    # events live in memory only, no persistence. sliding window keeps a
    # transient spike from firing while still catching sustained problems.
    def evaluate(
        self, event: dict[str, Any], rules: list[AlertRule]
    ) -> list[AlertRule]:
        event_type = event.get("event_type")
        event_ts = event.get("timestamp")
        event_timestamp = event_ts if isinstance(event_ts, datetime) else self._utcnow()

        if event_timestamp.tzinfo is None:
            event_timestamp = event_timestamp.replace(tzinfo=timezone.utc)

        triggered: list[AlertRule] = []
        for rule in rules:
            if not rule.enabled or rule.condition != event_type:
                continue

            timestamps = self._events_by_rule.setdefault(rule.rule_id, [])
            timestamps.append(event_timestamp)

            window_start = event_timestamp.timestamp() - rule.window_seconds
            self._events_by_rule[rule.rule_id] = [
                ts for ts in timestamps if ts.timestamp() >= window_start
            ]

            if len(self._events_by_rule[rule.rule_id]) >= rule.threshold:
                triggered.append(rule)
                logger.info("Alert triggered: %s (rule_id=%s)", rule.name, rule.rule_id)

        return triggered

    @staticmethod
    def _utcnow() -> datetime:
        return datetime.now(timezone.utc)


class NotificationDispatcher:
    def __init__(self) -> None:
        self._breaker = get_circuit_breaker(service_name="monitoring_notifications")

    async def send_webhook(self, url: str, payload: dict[str, Any]) -> bool:
        return await self._post_json_with_retry(url=url, payload=payload)

    async def send_slack(self, webhook_url: str, message: str) -> bool:
        payload = {"text": message}
        return await self._post_json_with_retry(url=webhook_url, payload=payload)

    async def _post_json_with_retry(
        self,
        url: str,
        payload: dict[str, Any],
        max_attempts: int = 3,
        base_backoff_seconds: float = 0.5,
    ) -> bool:
        body = json.dumps(payload).encode("utf-8")

        for attempt in range(1, max_attempts + 1):
            try:
                request = urllib_request.Request(
                    url,
                    data=body,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )

                def _send() -> bool:
                    with urllib_request.urlopen(request, timeout=5) as response:
                        return 200 <= cast(int, response.status) < 300

                if await self._breaker.execute(_send):
                    return True
            except Exception as exc:
                is_last_attempt = attempt == max_attempts
                if is_last_attempt:
                    logger.warning(
                        "Notification delivery failed after retries (url=%s): %s",
                        url,
                        exc,
                    )
                    return False

                backoff = base_backoff_seconds * (2 ** (attempt - 1))
                await asyncio.sleep(backoff)

        return False


class RedisAlertStore:
    # redis-backed variant so alert state is shared when running multiple workers
    def __init__(
        self,
        redis_client: redis.Redis | None,
        key_prefix: str = "alert_rule",
        ttl_seconds: int = 86400,
    ) -> None:
        self.redis = redis_client
        self.key_prefix = key_prefix
        self.ttl_seconds = ttl_seconds

    def _key(self, rule_id: str) -> str:
        return f"{self.key_prefix}:{rule_id}"

    async def list_rules(self) -> list[AlertRule]:
        if self.redis is None:
            return []

        keys = await self.redis.keys(f"{self.key_prefix}:*")
        rules: list[AlertRule] = []
        for key in keys:
            payload = await self.redis.get(key)
            if payload is None:
                continue
            try:
                parsed = json.loads(payload)
                rules.append(AlertRule.model_validate(parsed))
            except Exception as exc:
                logger.warning("Invalid alert rule payload at key=%s: %s", key, exc)
        return rules

    async def add_rule(self, rule: AlertRule) -> None:
        if self.redis is None:
            return
        key = self._key(rule.rule_id)
        payload = rule.model_dump_json()
        await self.redis.setex(key, self.ttl_seconds, payload)
        logger.info(
            "Alert rule %s persisted to Redis (ttl=%ds)",
            rule.rule_id,
            self.ttl_seconds,
        )

    async def remove_rule(self, rule_id: str) -> bool:
        if self.redis is None:
            return False
        deleted = await self.redis.delete(self._key(rule_id))
        return bool(deleted)

    async def _cleanup_expired(self) -> int:
        if self.redis is None:
            return 0

        removed = 0
        keys = await self.redis.keys(f"{self.key_prefix}:*")
        for key in keys:
            ttl = await self.redis.ttl(key)
            if ttl == -1:
                removed += int(await self.redis.delete(key))
        logger.info("Redis alert rule cleanup removed %d stale keys", removed)
        return removed


class MonitoringHub:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._clients.add(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(websocket)

    async def broadcast(self, event: dict[str, Any]) -> None:
        payload = self._serialize_event(event)
        async with self._lock:
            clients = list(self._clients)

        stale_clients: list[WebSocket] = []
        for client in clients:
            try:
                await client.send_json(payload)
            except Exception:
                stale_clients.append(client)

        if stale_clients:
            async with self._lock:
                for client in stale_clients:
                    self._clients.discard(client)

    @staticmethod
    def _serialize_event(event: dict[str, Any]) -> dict[str, Any]:
        serialized: dict[str, Any] = {}
        for key, value in event.items():
            if isinstance(value, datetime):
                serialized[key] = value.isoformat()
            else:
                serialized[key] = value
        return serialized


_MONITORING_HUB = MonitoringHub()
_ALERT_EVALUATOR = AlertEvaluator()
_NOTIFICATION_DISPATCHER = NotificationDispatcher()

_ALERT_STORE: RedisAlertStore | None = None
_IN_MEMORY_ALERT_RULES: dict[str, AlertRule] = {}
_ALERT_STORE_FALLBACK_WARNED = False


async def _get_alert_store() -> RedisAlertStore:
    global _ALERT_STORE
    global _ALERT_STORE_FALLBACK_WARNED

    if _ALERT_STORE is not None:
        return _ALERT_STORE

    redis_client = await get_redis_client()
    if redis_client is None and not _ALERT_STORE_FALLBACK_WARNED:
        logger.warning(
            "Redis unavailable for alert store; falling back to in-memory. hint: verify SHIELDEYE_REDIS_URL"
        )
        _ALERT_STORE_FALLBACK_WARNED = True

    _ALERT_STORE = RedisAlertStore(redis_client=redis_client)
    # TODO: expire stale alert state with a periodic cleanup task
    return _ALERT_STORE


async def list_alert_rules() -> list[AlertRule]:
    store = await _get_alert_store()
    if store.redis is None:
        # no redis configured - keep rules in memory
        return list(_IN_MEMORY_ALERT_RULES.values())
    return await store.list_rules()


async def add_alert_rule(rule: AlertRule) -> AlertRule:
    store = await _get_alert_store()
    if store.redis is None:
        # no redis configured - keep rules in memory
        _IN_MEMORY_ALERT_RULES[rule.rule_id] = rule
        return rule

    await store.add_rule(rule)
    return rule


async def remove_alert_rule(rule_id: str) -> AlertRule | None:
    store = await _get_alert_store()
    if store.redis is None:
        # no redis configured - keep rules in memory
        return _IN_MEMORY_ALERT_RULES.pop(rule_id, None)

    existing_rule = next(
        (rule for rule in await store.list_rules() if rule.rule_id == rule_id),
        None,
    )
    removed = await store.remove_rule(rule_id)
    if removed:
        return existing_rule
    return None


def _build_alert_payload(rule: AlertRule, event: dict[str, Any]) -> dict[str, Any]:
    # Compliance scenario example: alert when CIS-4.1.3 fails 3x in 5 minutes.
    return {
        "event_type": "compliance_alert",
        "rule": {
            "rule_id": rule.rule_id,
            "name": rule.name,
            "condition": rule.condition,
            "threshold": rule.threshold,
            "window_seconds": rule.window_seconds,
        },
        "event": MonitoringHub._serialize_event(event),
        "sent_at": datetime.now(timezone.utc).isoformat(),
    }


async def _dispatch_triggered_alerts(
    triggered_rules: list[AlertRule], event: dict[str, Any]
) -> None:
    config = get_config()
    webhook_url = getattr(config, "monitoring_webhook_url", "")

    for rule in triggered_rules:
        if "webhook" not in rule.notification_channels:
            continue
        if not webhook_url:
            logger.warning(
                "Alert %s triggered but monitoring_webhook_url is not configured. hint: verify webhook_url is reachable and accepts JSON payloads",
                rule.rule_id,
            )
            continue

        payload = _build_alert_payload(rule, event)
        dispatched = await _NOTIFICATION_DISPATCHER.send_webhook(webhook_url, payload)
        if dispatched:
            logger.info(
                "Alert dispatched: %s via webhook (rule_id=%s)",
                rule.name,
                rule.rule_id,
            )
        else:
            logger.warning(
                "Alert dispatch failed for rule_id=%s. hint: verify webhook_url is reachable and accepts JSON payloads",
                rule.rule_id,
            )


def _is_realtime_monitoring_enabled() -> bool:
    return bool(getattr(get_config(), "enable_realtime_monitoring", False))


def _authenticate_ws_token(token: str | None) -> bool:
    if not token:
        return False
    auth = get_auth_manager()
    try:
        api_key = auth.validate_api_key(token)
        return auth.users.get(api_key.username) is not None
    except AuthenticationError:
        return False


# websocket feed so the dashboard gets pushes instead of polling
@monitoring_router.websocket("/ws/monitoring")  # type: ignore[misc]
async def monitoring_websocket(
    websocket: WebSocket,
    token: str = Query(default=""),
) -> None:
    if not _is_realtime_monitoring_enabled() or not _authenticate_ws_token(token):
        await websocket.close(code=1008)
        return

    await _MONITORING_HUB.connect(websocket)

    try:
        while True:
            message: Any = await websocket.receive_json()
            if isinstance(message, dict):
                event = {
                    "event_type": str(message.get("event_type", "heartbeat")),
                    "control_id": str(message.get("control_id", "unknown")),
                    "target": str(message.get("target", "unknown")),
                    "timestamp": datetime.now(timezone.utc),
                    **message,
                }
                triggered = _ALERT_EVALUATOR.evaluate(event, await list_alert_rules())
                if triggered:
                    event["triggered_rules"] = [rule.rule_id for rule in triggered]
                    await _dispatch_triggered_alerts(triggered, event)
                await _MONITORING_HUB.broadcast(event)
    except WebSocketDisconnect:
        logger.warning(
            "WebSocket client disconnected. hint: check network stability or token expiry"
        )
    finally:
        await _MONITORING_HUB.disconnect(websocket)
