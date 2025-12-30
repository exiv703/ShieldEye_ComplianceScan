from __future__ import annotations

import json
import requests
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum

from ..utils.logging_config import get_logger

logger = get_logger("webhooks")

class WebhookEvent(Enum):
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    CRITICAL_FINDING = "finding.critical"
    HIGH_FINDING = "finding.high"
    SCORE_THRESHOLD = "score.threshold"

@dataclass
class WebhookPayload:
    
    event: str
    timestamp: str
    scan_id: str
    url: str
    data: Dict[str, Any]

class WebhookManager:
    
    def __init__(self):
        self.subscriptions: Dict[str, List[str]] = {}
        self.delivery_timeout = 10
    
    def subscribe(self, event: WebhookEvent, webhook_url: str) -> None:

        event_name = event.value
        
        if event_name not in self.subscriptions:
            self.subscriptions[event_name] = []
        
        if webhook_url not in self.subscriptions[event_name]:
            self.subscriptions[event_name].append(webhook_url)
            logger.info(f"Subscribed {webhook_url} to {event_name}")
    
    def unsubscribe(self, event: WebhookEvent, webhook_url: str) -> bool:

        event_name = event.value
        
        if event_name in self.subscriptions and webhook_url in self.subscriptions[event_name]:
            self.subscriptions[event_name].remove(webhook_url)
            logger.info(f"Unsubscribed {webhook_url} from {event_name}")
            return True
        
        return False
    
    def trigger(
        self,
        event: WebhookEvent,
        scan_id: str,
        url: str,
        data: Dict[str, Any]
    ) -> None:

        event_name = event.value
        
        if event_name not in self.subscriptions:
            return
        
        payload = WebhookPayload(
            event=event_name,
            timestamp=datetime.utcnow().isoformat() + "Z",
            scan_id=scan_id,
            url=url,
            data=data
        )
        
        for webhook_url in self.subscriptions[event_name]:
            self._deliver_webhook(webhook_url, payload)
    
    def _deliver_webhook(self, webhook_url: str, payload: WebhookPayload) -> None:

        try:
            response = requests.post(
                webhook_url,
                json=asdict(payload),
                timeout=self.delivery_timeout,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "ShieldEye-Webhook/1.0",
                }
            )
            
            if response.status_code >= 200 and response.status_code < 300:
                logger.debug(f"Webhook delivered to {webhook_url}: {response.status_code}")
            else:
                logger.warning(
                    f"Webhook delivery failed to {webhook_url}: "
                    f"HTTP {response.status_code}"
                )
        
        except requests.RequestException as e:
            logger.error(f"Failed to deliver webhook to {webhook_url}: {e}")
    
    def list_subscriptions(self) -> Dict[str, List[str]]:
        return dict(self.subscriptions)

_global_webhook_manager: Optional[WebhookManager] = None

def get_webhook_manager() -> WebhookManager:
    global _global_webhook_manager
    if _global_webhook_manager is None:
        _global_webhook_manager = WebhookManager()
    return _global_webhook_manager
