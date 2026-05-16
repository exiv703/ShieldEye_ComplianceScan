from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from backend.utils.logging_config import get_logger
from benchmark.engine import get_control_mapping

if TYPE_CHECKING:
    from reporting.generator import ComplianceReport

logger = get_logger("reporting.wizard")


class RemediationStep(BaseModel):  # type: ignore[misc]  # Pydantic BaseModel metaclass typing is treated as Any under strict stubs
    step_id: str
    control_id: str
    title: str
    command: str
    validation_check: str
    expected_output: str
    rollback_command: str
    status: Literal["pending", "in_progress", "passed", "failed", "rolled_back"] = (
        "pending"
    )
    executed_at: datetime | None = None


class RemediationWizard:
    def __init__(self, report: ComplianceReport, target: str) -> None:
        self.report = report
        self.target = target
        self._steps: list[RemediationStep] = []
        self._steps_by_id: dict[str, RemediationStep] = {}

    def generate_steps(self) -> list[RemediationStep]:
        steps: list[RemediationStep] = []
        seen_controls: set[str] = set()

        # v2: added template rendering after audit flagged unresolved placeholders
        for result in self.report.results:
            if result.status not in ("failed", "error"):
                continue
            if result.control_id in seen_controls:
                continue

            mapping = get_control_mapping(result.control_id)
            if mapping is None:
                continue

            seen_controls.add(result.control_id)
            step_id = f"step-{len(steps) + 1}-{result.control_id}"

            template = self.report.remediation_snippets.get(
                result.control_id,
                mapping.remediation_template,
            )

            context = self._build_template_context(result.control_id)
            try:
                command = self._render_command(template, context, result.control_id)
                step_status: Literal[
                    "pending", "in_progress", "passed", "failed", "rolled_back"
                ] = "pending"
                validation_check = mapping.check_command
                expected_output = mapping.expected_output
            except ValueError as exc:
                command = f"echo '{exc}'"
                step_status = "failed"
                validation_check = f"render_error: {exc}"
                expected_output = f"render_error: {exc}"

            step = RemediationStep(
                step_id=step_id,
                control_id=result.control_id,
                title=f"Remediate control {result.control_id}",
                command=command,
                validation_check=validation_check,
                expected_output=expected_output,
                rollback_command=self._build_rollback_command(
                    command, result.control_id
                ),
                status=step_status,
            )
            steps.append(step)

        self._steps = steps
        self._steps_by_id = {step.step_id: step for step in steps}
        return steps

    # Why validation_check? Ensures copy-paste fixes actually resolve the control gap
    def validate_step(self, step_id: str, actual_output: str) -> bool:
        step = self._get_step(step_id)
        step.status = "in_progress"

        passed = self._matches_expected_output(step.expected_output, actual_output)
        step.executed_at = datetime.now(timezone.utc)

        if passed:
            step.status = "passed"
            logger.info("Remediation step %s executed: %s", step_id, step.status)
            return True

        step.status = "failed"
        logger.info("Remediation step %s executed: %s", step_id, step.status)
        # Why specific hints? Operators need actionable next steps, not just 'FAIL'
        logger.warning(
            "Validation failed for %s: expected '%s' but got '%s'. hint: %s",
            step.control_id,
            step.expected_output,
            actual_output.strip() or "<empty>",
            self._validation_hint(step.control_id),
        )
        return False

    # Why rollback_command? Enables safe experimentation without permanent config drift
    def rollback_step(self, step_id: str) -> str:
        step = self._get_step(step_id)
        step.status = "rolled_back"
        step.executed_at = datetime.now(timezone.utc)
        logger.info("Remediation step %s executed: %s", step_id, step.status)
        return step.rollback_command

    def get_progress(self) -> dict[str, Any]:
        total = len(self._steps)
        passed = sum(1 for step in self._steps if step.status == "passed")
        failed = sum(1 for step in self._steps if step.status == "failed")
        percent = round((passed / total) * 100.0, 2) if total else 0.0
        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "percent": percent,
        }

    def _get_step(self, step_id: str) -> RemediationStep:
        step = self._steps_by_id.get(step_id)
        if step is None:
            raise ValueError(f"Unknown remediation step_id: {step_id}")
        return step

    def _matches_expected_output(
        self, expected_output: str, actual_output: str
    ) -> bool:
        try:
            if re.search(expected_output, actual_output, re.IGNORECASE):
                return True
        except re.error:
            pass
        return expected_output.strip().lower() in actual_output.strip().lower()

    def _build_rollback_command(self, command: str, control_id: str) -> str:
        normalized = command.replace("\n", " ")

        match = re.search(
            r"systemctl\s+enable\s+--now\s+([A-Za-z0-9_.@-]+)", normalized
        )
        if match:
            service = match.group(1)
            return f"sudo systemctl disable --now {service}"

        return (
            "echo 'Manual rollback required for "
            + control_id
            + ". Revert configuration changes using backups or change management history.'"
        )

    def _build_template_context(self, control_id: str) -> dict[str, str]:
        parsed_hostname = urlparse(self.report.target).hostname or self.report.target
        context = {
            "target": self.report.target,
            "host": parsed_hostname,
            "domain": self.report.target,
        }
        if control_id == "CIS-4.1.3":
            context["package"] = "auditd"
        if control_id == "GDPR-32.1.1":
            context["domain"] = self.report.target
            context["host"] = parsed_hostname
        return context

    def _render_command(
        self, template: str, context: dict[str, str], control_id: str
    ) -> str:
        command = template
        for key, value in context.items():
            command = command.replace(f"{{{key}}}", value)

        missing_keys = sorted(set(re.findall(r"\{([A-Za-z0-9_]+)\}", command)))
        if missing_keys:
            logger.warning(
                "Remediation template rendering failed for %s; missing keys=%s",
                control_id,
                ",".join(missing_keys),
            )
            key = missing_keys[0]
            if control_id == "GDPR-32.1.1" and key == "domain":
                raise ValueError(
                    "hint: missing {domain} for GDPR-32.1.1 — add target hostname to context"
                )
            if control_id == "CIS-4.1.3" and key == "package":
                raise ValueError(
                    "hint: missing {package} for CIS-4.1.3 — expected 'auditd' for RHEL/Ubuntu"
                )
            raise ValueError(
                f"hint: missing {{{key}}} for {control_id} — update remediation context before execution"
            )

        # Why fail closed? Prevents operators from executing incomplete commands
        return command

    def _validation_hint(self, control_id: str) -> str:
        if control_id == "CIS-4.1.3":
            return "run 'sudo systemctl enable --now auditd' then re-check"
        if control_id == "GDPR-32.1.1":
            return "renew certificate (for example: sudo certbot certonly --standalone -d <domain>) then re-check"
        return "check command output, target reachability, and remediation context"


# Impact: Adds operator-safe, stepwise remediation with validation and rollback guidance to improve trust and reduce misconfiguration risk during compliance fix execution.
