from __future__ import annotations

import os
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Literal, Sequence

import requests  # type: ignore[import-untyped]
from pydantic import BaseModel, Field

from backend.utils.logging_config import get_logger

if TYPE_CHECKING:
    from reporting.generator import ComplianceReport
    from reporting.wizard import RemediationStep

logger = get_logger("reporting.grc_payload_formatters")

# This module only shapes payloads and hands them to the webhook dispatcher.
# TODO: authenticated ServiceNow/Drata/Vanta clients for direct API transport.


class GRCExportResult(BaseModel):  # type: ignore[misc]
    export_id: str
    platform: Literal["servicenow", "drata", "vanta"]
    status: Literal["success", "partial", "failed"]
    external_ids: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    exported_at: datetime
    webhook_queued: bool = False


def _placeholder_external_ref(platform: str, batch_index: int) -> str:
    # not a real vendor id - just a trace label for the webhook batch
    return f"<{platform}_batch_{batch_index}>"


class WebhookSyncMixin:
    """Reliable webhook delivery helper used by payload formatters."""

    def _sync_webhook_with_retry(
        self,
        webhook_url: str,
        payload: dict[str, Any],
        *,
        max_retries: int = 3,
        timeout_seconds: float = 10.0,
        backoff_seconds: float = 1.0,
    ) -> bool:
        for attempt in range(max_retries + 1):
            try:
                response = requests.post(
                    webhook_url,
                    json=payload,
                    timeout=timeout_seconds,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "ShieldEye-GRCExport/1.0",
                    },
                )
                if 200 <= response.status_code < 300:
                    logger.info(
                        "Webhook sync delivered to %s (attempt=%d)",
                        webhook_url,
                        attempt + 1,
                    )
                    return True

                logger.warning(
                    "Webhook sync failed to %s with HTTP %d (attempt=%d/%d). hint: verify endpoint auth and payload schema",
                    webhook_url,
                    response.status_code,
                    attempt + 1,
                    max_retries + 1,
                )
            except requests.RequestException as exc:
                logger.warning(
                    "Webhook sync request error for %s (attempt=%d/%d): %s. hint: verify webhook reachability and TLS settings",
                    webhook_url,
                    attempt + 1,
                    max_retries + 1,
                    exc,
                )

            if attempt < max_retries:
                time.sleep(backoff_seconds * (2**attempt))

        return False

    def queue_webhook_sync(
        self,
        webhook_url: str,
        payload: dict[str, Any],
        *,
        max_retries: int = 3,
        timeout_seconds: float = 10.0,
        backoff_seconds: float = 1.0,
    ) -> threading.Thread:
        thread = threading.Thread(
            target=self._sync_webhook_with_retry,
            kwargs={
                "webhook_url": webhook_url,
                "payload": payload,
                "max_retries": max_retries,
                "timeout_seconds": timeout_seconds,
                "backoff_seconds": backoff_seconds,
            },
            daemon=True,
        )
        thread.start()
        return thread


class _BasePayloadFormatter(WebhookSyncMixin):
    platform: Literal["servicenow", "drata", "vanta"]

    def __init__(self, webhook_url: str | None = None, batch_size: int = 100):
        self.webhook_url = webhook_url
        self.batch_size = max(1, batch_size)

    # split into batches so a single payload stays under platform API limits
    def _batched(self, records: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
        return [
            records[index : index + self.batch_size]
            for index in range(0, len(records), self.batch_size)
        ]

    def _build_result(
        self,
        external_ids: list[str],
        errors: list[str],
        webhook_queued: bool,
    ) -> GRCExportResult:
        if external_ids and errors:
            status: Literal["success", "partial", "failed"] = "partial"
        elif external_ids:
            status = "success"
        else:
            status = "failed"

        result = GRCExportResult(
            export_id=str(uuid.uuid4()),
            platform=self.platform,
            status=status,
            external_ids=external_ids,
            errors=errors,
            exported_at=datetime.now(timezone.utc),
            webhook_queued=webhook_queued,
        )

        if result.status == "partial":
            logger.warning(
                "%s export completed partially (%d external IDs, %d errors). hint: review mapper errors and rerun export for failed controls",
                self.platform,
                len(result.external_ids),
                len(result.errors),
            )
        elif result.status == "failed":
            logger.warning(
                "%s export failed with %d errors. hint: verify platform credentials and source report content",
                self.platform,
                len(result.errors),
            )
        else:
            logger.info(
                "%s export completed successfully (%d records)",
                self.platform,
                len(result.external_ids),
            )

        return result


class ServiceNowPayloadFormatter(_BasePayloadFormatter):
    platform: Literal["servicenow"] = "servicenow"

    def __init__(
        self,
        instance_url: str,
        api_key: str,
        webhook_url: str | None = None,
        batch_size: int = 100,
    ):
        super().__init__(webhook_url=webhook_url, batch_size=batch_size)
        self.instance_url = instance_url.rstrip("/")
        self.api_key = api_key

    def _map_records(
        self,
        report: ComplianceReport,
        steps: Sequence[RemediationStep],
    ) -> tuple[list[dict[str, Any]], list[str]]:
        step_by_control = {step.control_id: step for step in steps}
        records: list[dict[str, Any]] = []
        errors: list[str] = []

        for benchmark_result in report.results:
            try:
                step = step_by_control.get(benchmark_result.control_id)
                records.append(
                    {
                        "u_report_id": report.report_id,
                        "u_target": report.target,
                        "u_control_id": benchmark_result.control_id,
                        "u_status": benchmark_result.status,
                        "u_execution_output": benchmark_result.output,
                        "u_summary": report.summary,
                        "u_remediation_command": (
                            step.command
                            if step is not None
                            else report.remediation_snippets.get(
                                benchmark_result.control_id, ""
                            )
                        ),
                        "u_validation_check": (
                            step.validation_check if step is not None else ""
                        ),
                        "u_exported_at": datetime.now(timezone.utc).isoformat(),
                    }
                )
            except Exception as exc:
                errors.append(
                    f"Failed to map control {benchmark_result.control_id} for ServiceNow: {exc}"
                )

        return records, errors

    def export(
        self,
        report: ComplianceReport,
        wizard_steps: Sequence[RemediationStep],
    ) -> GRCExportResult:
        """Format ServiceNow-compatible payload batches and optionally queue webhook sync."""
        records, errors = self._map_records(report, wizard_steps)
        external_ids: list[str] = []

        for batch_index, batch in enumerate(self._batched(records), start=1):
            external_id = _placeholder_external_ref("service_now", batch_index)
            external_ids.append(external_id)
            logger.info(
                "Prepared ServiceNow batch %d with %d records (external_id=%s)",
                batch_index,
                len(batch),
                external_id,
            )

        webhook_queued = False
        if self.webhook_url:
            payload = {
                "platform": self.platform,
                "instance_url": self.instance_url,
                "exported_records": records,
                "api_key_present": bool(self.api_key),
            }
            self.queue_webhook_sync(self.webhook_url, payload)
            webhook_queued = True

        if not records:
            errors.append("No ServiceNow export records generated")

        return self._build_result(external_ids, errors, webhook_queued)


class DrataPayloadFormatter(_BasePayloadFormatter):
    platform: Literal["drata"] = "drata"

    def __init__(
        self,
        workspace_id: str,
        api_key: str,
        webhook_url: str | None = None,
        batch_size: int = 100,
    ):
        super().__init__(webhook_url=webhook_url, batch_size=batch_size)
        self.workspace_id = workspace_id
        self.api_key = api_key

    def _map_records(
        self,
        report: ComplianceReport,
        steps: Sequence[RemediationStep],
    ) -> list[dict[str, Any]]:
        step_by_control = {step.control_id: step for step in steps}
        records: list[dict[str, Any]] = []

        for benchmark_result in report.results:
            step = step_by_control.get(benchmark_result.control_id)
            records.append(
                {
                    "workspace_id": self.workspace_id,
                    "report_id": report.report_id,
                    "target": report.target,
                    "control": benchmark_result.control_id,
                    "result": benchmark_result.status,
                    "evidence": {
                        "scanner_output": benchmark_result.output,
                        "remediation": report.remediation_snippets.get(
                            benchmark_result.control_id, ""
                        ),
                        "wizard_step": (
                            {
                                "step_id": step.step_id,
                                "command": step.command,
                                "validation_check": step.validation_check,
                            }
                            if step is not None
                            else None
                        ),
                    },
                    "summary": report.summary,
                    "timestamp": report.timestamp.isoformat(),
                }
            )

        return records

    def export(
        self,
        report: ComplianceReport,
        wizard_steps: Sequence[RemediationStep],
    ) -> GRCExportResult:
        """Format Drata-compatible payload batches and optionally queue webhook sync."""
        records = self._map_records(report, wizard_steps)
        external_ids: list[str] = []
        errors: list[str] = []

        for batch_index, batch in enumerate(self._batched(records), start=1):
            external_id = _placeholder_external_ref("drata", batch_index)
            external_ids.append(external_id)
            logger.info(
                "Prepared Drata batch %d with %d records (external_id=%s)",
                batch_index,
                len(batch),
                external_id,
            )

        webhook_queued = False
        if self.webhook_url:
            payload = {
                "platform": self.platform,
                "workspace_id": self.workspace_id,
                "exported_records": records,
                "api_key_present": bool(self.api_key),
            }
            self.queue_webhook_sync(self.webhook_url, payload)
            webhook_queued = True

        if not records:
            errors.append("No Drata export records generated")

        return self._build_result(external_ids, errors, webhook_queued)


class VantaPayloadFormatter(_BasePayloadFormatter):
    platform: Literal["vanta"] = "vanta"

    def __init__(
        self,
        tenant_id: str,
        api_key: str,
        webhook_url: str | None = None,
        batch_size: int = 100,
    ):
        super().__init__(webhook_url=webhook_url, batch_size=batch_size)
        self.tenant_id = tenant_id
        self.api_key = api_key

    def _map_records(
        self,
        report: ComplianceReport,
        steps: Sequence[RemediationStep],
    ) -> list[dict[str, Any]]:
        step_by_control = {step.control_id: step for step in steps}
        records: list[dict[str, Any]] = []

        for benchmark_result in report.results:
            step = step_by_control.get(benchmark_result.control_id)
            records.append(
                {
                    "tenant_id": self.tenant_id,
                    "scan_id": report.report_id,
                    "asset": report.target,
                    "control_id": benchmark_result.control_id,
                    "state": benchmark_result.status,
                    "evidence_text": benchmark_result.output,
                    "remediation": {
                        "snippet": report.remediation_snippets.get(
                            benchmark_result.control_id, ""
                        ),
                        "step_id": step.step_id if step is not None else None,
                    },
                    "captured_at": report.timestamp.isoformat(),
                }
            )

        return records

    def export(
        self,
        report: ComplianceReport,
        wizard_steps: Sequence[RemediationStep],
    ) -> GRCExportResult:
        """Format Vanta-compatible payload batches and optionally queue webhook sync."""
        records = self._map_records(report, wizard_steps)
        external_ids: list[str] = []
        errors: list[str] = []

        for batch_index, batch in enumerate(self._batched(records), start=1):
            external_id = _placeholder_external_ref("vanta", batch_index)
            external_ids.append(external_id)
            logger.info(
                "Prepared Vanta batch %d with %d records (external_id=%s)",
                batch_index,
                len(batch),
                external_id,
            )

        webhook_queued = False
        if self.webhook_url:
            payload = {
                "platform": self.platform,
                "tenant_id": self.tenant_id,
                "exported_records": records,
                "api_key_present": bool(self.api_key),
            }
            self.queue_webhook_sync(self.webhook_url, payload)
            webhook_queued = True

        if not records:
            errors.append("No Vanta export records generated")

        return self._build_result(external_ids, errors, webhook_queued)


def create_grc_payload_formatter(
    platform: str,
    *,
    webhook_url: str | None,
) -> _BasePayloadFormatter:
    normalized = platform.strip().lower()

    if normalized == "servicenow":
        instance_url = os.getenv("GRC_SERVICENOW_INSTANCE_URL", "")
        api_key = os.getenv("GRC_SERVICENOW_API_KEY", "")
        if not instance_url:
            logger.warning(
                "ServiceNow instance URL is not configured. hint: set GRC_SERVICENOW_INSTANCE_URL"
            )
        return ServiceNowPayloadFormatter(
            instance_url=instance_url or "https://example.service-now.com",
            api_key=api_key,
            webhook_url=webhook_url,
        )

    if normalized == "drata":
        workspace_id = os.getenv("GRC_DRATA_WORKSPACE_ID", "default")
        api_key = os.getenv("GRC_DRATA_API_KEY", "")
        if workspace_id == "default":
            logger.warning(
                "Drata workspace ID is using default value. hint: set GRC_DRATA_WORKSPACE_ID for production payload routing"
            )
        return DrataPayloadFormatter(
            workspace_id=workspace_id,
            api_key=api_key,
            webhook_url=webhook_url,
        )

    if normalized == "vanta":
        tenant_id = os.getenv("GRC_VANTA_TENANT_ID", "default")
        api_key = os.getenv("GRC_VANTA_API_KEY", "")
        if tenant_id == "default":
            logger.warning(
                "Vanta tenant ID is using default value. hint: set GRC_VANTA_TENANT_ID for production payload routing"
            )
        return VantaPayloadFormatter(
            tenant_id=tenant_id,
            api_key=api_key,
            webhook_url=webhook_url,
        )

    raise ValueError(f"Unsupported GRC platform: {platform}")
