"""HTTP client for importing SurfaceScan findings and mapping them to controls."""

# mypy: ignore-errors

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime
from typing import Literal
from urllib.parse import quote, urlparse

import requests
from pydantic import BaseModel
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from integrations.correlation import CorrelationEngine, get_correlation_engine

logger = logging.getLogger("shieldeye.integrations.surfacescan")


class SurfaceFinding(BaseModel):
    finding_id: str
    target_url: str
    category: Literal["ssl", "headers", "cookies", "privacy", "tracking"]
    severity: Literal["critical", "high", "medium", "low"]
    description: str
    remediation_hint: str
    timestamp: datetime


_CONTROL_DESCRIPTIONS: dict[str, str] = {
    "CIS-4.1.3": "Ensure auditd is configured for security event telemetry",
    "CIS-4.2.1": "Ensure logging configuration is hardened for forensic traceability",
    "CIS-5.1.1": "Ensure SSH daemon is configured",
    "GDPR-32.1.1": "Ensure data encryption in transit",
    "GDPR-32.2.1": "Ensure consent/security headers are consistently applied",
}


class SurfaceScanClient:
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

    def get_findings(self, target_url: str) -> list[SurfaceFinding]:
        encoded_url = quote(target_url, safe="")
        url = f"{self.base_url}/api/findings?url={encoded_url}"
        try:
            response = self.session.get(url, timeout=self.timeout)
        except requests.Timeout:
            logger.warning(
                "SurfaceScan API timeout for %s — check network or increase timeout",
                target_url,
            )
            return []
        except requests.RequestException as exc:
            logger.warning("SurfaceScan API request failed for %s: %s", target_url, exc)
            return []

        if response.status_code == 404:
            logger.info("SurfaceScan 404 for %s — probably no findings", target_url)
            return []

        response.raise_for_status()

        try:
            data = response.json()
        except ValueError:
            logger.warning("SurfaceScan API returned invalid JSON")
            return []

        if not isinstance(data, list):
            data = data.get("findings", []) if isinstance(data, dict) else []

        results: list[SurfaceFinding] = []
        for item in data:
            try:
                results.append(SurfaceFinding.model_validate(item))
            except Exception:
                logger.warning("SurfaceScan API returned unexpected schema")
                continue

        return results

    def correlate_to_control(self, finding: SurfaceFinding, control_id: str) -> bool:
        engine = get_correlation_engine()
        control_description = _CONTROL_DESCRIPTIONS.get(control_id, "")
        result = engine.correlate(
            finding.description,
            control_description,
            finding.category,
            control_id,
        )
        if result["matched"] is True:
            logger.info(
                "Correlation matched finding %s to %s via %s (reason=%s)",
                finding.finding_id,
                control_id,
                result.get("method", "unknown"),
                result.get("reason", "unknown"),
            )
            return True
        if result["method"] == "heuristic":
            logger.debug(
                "Heuristic fallback used for control %s: %s",
                control_id,
                result.get("reason", "unknown"),
            )
        else:
            logger.debug(
                "ML correlation rejected for control %s: %s",
                control_id,
                result.get("reason", "unknown"),
            )
        return False

    def correlate_findings_to_control(
        self, findings: list[SurfaceFinding], control_id: str
    ) -> list[SurfaceFinding]:
        correlated = [f for f in findings if self.correlate_to_control(f, control_id)]
        logger.info(
            "Correlated %d SurfaceScan findings to control %s",
            len(correlated),
            control_id,
        )
        return correlated
