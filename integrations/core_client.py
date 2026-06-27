"""HTTP client for pulling completed scans from ShieldEye-Core safely."""

# mypy: ignore-errors

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

import requests
from pydantic import BaseModel, Field
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("shieldeye.integrations.core")


class CoreScanResult(BaseModel):
    scan_id: str
    target_url: str
    findings: list[dict[str, Any]]
    timestamp: datetime
    metadata: dict[str, str] = Field(default_factory=dict)


class CoreClient:
    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        timeout: int = 30,
        allow_internal: bool = False,
    ):
        self.base_url = self._validate_base_url(base_url, allow_internal=allow_internal)
        self.api_key = api_key
        self.timeout = timeout
        self.allow_internal = allow_internal
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.verify = True

        if self.api_key:
            session.headers.update({"Authorization": f"Bearer {self.api_key}"})
        session.headers.update(
            {"Content-Type": "application/json", "Accept": "application/json"}
        )
        return session

    @staticmethod
    def _validate_base_url(url: str, allow_internal: bool = False) -> str:
        if not url or not isinstance(url, str):
            raise ValueError("base_url must be a non-empty string")

        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("URL scheme must be http or https")
        if not parsed.netloc:
            raise ValueError("URL must have a valid domain")

        if not allow_internal:
            hostname = parsed.hostname or ""
            if hostname in ("localhost", "127.0.0.1", "::1"):
                raise ValueError("Localhost and private IP addresses are not allowed")
            ip_obj = None
            try:
                ip_obj = ipaddress.ip_address(hostname)
            except ValueError:
                pass
            if ip_obj is not None and (
                ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
            ):
                raise ValueError("Localhost and private IP addresses are not allowed")

        return url.rstrip("/")

    def get_scan_results(self, scan_id: str) -> CoreScanResult | None:
        url = f"{self.base_url}/api/scans/{scan_id}"
        try:
            response = self.session.get(url, timeout=self.timeout)
        except requests.Timeout:
            logger.warning(
                "Core API timeout for %s - check network or increase timeout", scan_id
            )
            return None
        except requests.RequestException as exc:
            logger.warning("Core API request failed for %s: %s", scan_id, exc)
            return None

        if response.status_code == 404:
            logger.warning("Core scan %s not found (404)", scan_id)
            return None

        response.raise_for_status()

        try:
            data = response.json()
        except ValueError:
            logger.warning("Core API returned invalid JSON for %s", scan_id)
            return None

        try:
            result = CoreScanResult.model_validate(data)
        except Exception:
            logger.warning("Core API returned unexpected schema for %s", scan_id)
            return None

        logger.info(
            "Imported %d findings from Core scan %s",
            len(result.findings),
            scan_id,
        )
        return result

    def list_recent_scans(self, limit: int = 50) -> list[CoreScanResult]:
        url = f"{self.base_url}/api/scans?limit={limit}"
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
        except requests.Timeout:
            logger.warning("Core API timeout for list_recent_scans")
            return []
        except requests.RequestException as exc:
            logger.warning("Core API request failed for list_recent_scans: %s", exc)
            return []

        try:
            data = response.json()
        except ValueError:
            logger.warning("Core API returned invalid JSON for list_recent_scans")
            return []

        if not isinstance(data, list):
            data = data.get("scans", []) if isinstance(data, dict) else []

        results: list[CoreScanResult] = []
        for item in data:
            status = item.get("status") if isinstance(item, dict) else None
            if status is not None and status != "completed":
                continue
            try:
                results.append(CoreScanResult.model_validate(item))
            except Exception:
                logger.warning("Core API returned unexpected schema for item")
                continue

        return results
