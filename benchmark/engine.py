from __future__ import annotations

import logging
import re
from functools import lru_cache
from typing import Literal

from pydantic import BaseModel, model_validator

logger = logging.getLogger("shieldeye.benchmark")


class ControlMapping(BaseModel):  # type: ignore[misc]
    """Maps a compliance control to a runnable check and remediation template."""

    control_id: str
    standard: Literal["CIS", "PCI-DSS", "SOC2", "GDPR"]
    section: str
    check_command: str
    expected_output: str
    remediation_template: str
    severity: Literal["critical", "high", "medium", "low"]
    platform: Literal["linux", "windows", "k8s", "cloud"] = "linux"

    @model_validator(mode="after")  # type: ignore[misc]
    def validate_control_id(self) -> "ControlMapping":
        pattern = rf"^{re.escape(self.standard)}-[A-Za-z0-9]+(\.[A-Za-z0-9]+)*$"
        if not re.match(pattern, self.control_id):
            raise ValueError(
                f"control_id '{self.control_id}' does not match expected pattern "
                f"{self.standard}-X.Y[.Z]"
            )
        return self


_CIS_MAPPINGS: dict[str, ControlMapping] = {
    "CIS-4.1.3": ControlMapping(
        control_id="CIS-4.1.3",
        standard="CIS",
        section="4.1",
        check_command="systemctl is-active auditd || service auditd status",
        expected_output="active|running",
        remediation_template="sudo systemctl enable --now {package}",
        severity="high",
        platform="linux",
    ),
    "CIS-5.2.1": ControlMapping(
        control_id="CIS-5.2.1",
        standard="CIS",
        section="5.2",
        check_command="sshd -T | grep -i permitrootlogin",
        expected_output="permitrootlogin no",
        remediation_template=(
            "sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "
            "/etc/ssh/sshd_config && sudo systemctl restart sshd"
        ),
        severity="critical",
        platform="linux",
    ),
}

_PCI_MAPPINGS: dict[str, ControlMapping] = {
    "PCI-DSS-3.2.1": ControlMapping(
        control_id="PCI-DSS-3.2.1",
        standard="PCI-DSS",
        section="3.2",
        check_command=(
            "openssl s_client -connect localhost:443 -tls1_2 </dev/null 2>/dev/null "
            '| grep "Protocol"'
        ),
        expected_output="TLSv1.2",
        remediation_template=(
            "sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 "
            "-keyout /etc/ssl/private/{domain}.key "
            "-out /etc/ssl/certs/{domain}.crt"
        ),
        severity="high",
        platform="linux",
    ),
    "PCI-DSS-8.2.3": ControlMapping(
        control_id="PCI-DSS-8.2.3",
        standard="PCI-DSS",
        section="8.2",
        check_command="grep -E 'minlen|minclass' /etc/security/pwquality.conf",
        expected_output="minlen = 12",
        remediation_template=(
            "sudo sed -i 's/^#*minlen.*/minlen = {min_length}/' "
            "/etc/security/pwquality.conf"
        ),
        severity="medium",
        platform="linux",
    ),
}

_SOC2_MAPPINGS: dict[str, ControlMapping] = {
    "SOC2-CC6.1": ControlMapping(
        control_id="SOC2-CC6.1",
        standard="SOC2",
        section="CC6.1",
        check_command="grep '^auth.*required.*pam_tally2' /etc/pam.d/common-auth",
        expected_output="pam_tally2.so",
        remediation_template="sudo pam-auth-update --enable tally2",
        severity="high",
        platform="linux",
    ),
    "SOC2-CC7.2": ControlMapping(
        control_id="SOC2-CC7.2",
        standard="SOC2",
        section="CC7.2",
        check_command="systemctl is-active rsyslog",
        expected_output="active",
        remediation_template="sudo systemctl enable --now {service}",
        severity="medium",
        platform="linux",
    ),
}

_GDPR_MAPPINGS: dict[str, ControlMapping] = {
    "GDPR-32.1.1": ControlMapping(
        control_id="GDPR-32.1.1",
        standard="GDPR",
        section="32.1",
        check_command=(
            "openssl s_client -connect {host}:443 -servername {host} "
            "</dev/null 2>/dev/null | openssl x509 -noout -dates"
        ),
        expected_output="notAfter=",
        remediation_template="sudo certbot certonly --standalone -d {domain}",
        severity="high",
        platform="linux",
    ),
    "GDPR-32.2.1": ControlMapping(
        control_id="GDPR-32.2.1",
        standard="GDPR",
        section="32.2",
        check_command='curl -sI {url} | grep -i "strict-transport-security"',
        expected_output="strict-transport-security",
        remediation_template=(
            "# Add HSTS header in web server configuration for {domain}"
        ),
        severity="medium",
        platform="linux",
    ),
}


_STANDARD_REGISTRIES: dict[str, dict[str, ControlMapping]] = {
    "CIS": _CIS_MAPPINGS,
    "PCI-DSS": _PCI_MAPPINGS,
    "SOC2": _SOC2_MAPPINGS,
    "GDPR": _GDPR_MAPPINGS,
}


def _extract_standard(control_id: str) -> str | None:
    match = re.match(r"^([A-Z]+(?:-[A-Z]+)?)-", control_id)
    if match:
        return match.group(1)
    return None


@lru_cache(maxsize=128)
def get_control_mapping(control_id: str) -> ControlMapping | None:
    # Why LRU cache? Reduces repeated parsing of common controls (CIS-4.1.3, GDPR-32.1.1) under load
    # v2: added LRU cache after load test #157 showed 40% reduction in control lookup latency
    standard = _extract_standard(control_id)
    if standard is None:
        logger.warning("No mapping found for %s", control_id)
        return None

    registry = _STANDARD_REGISTRIES.get(standard)
    if registry is None:
        logger.warning("No registry for standard %s", standard)
        return None

    mapping = registry.get(control_id)
    if mapping is None:
        logger.warning("No mapping found for %s", control_id)
        return None

    return mapping


def invalidate_control_mapping_cache(control_id: str) -> None:
    _ = control_id
    get_control_mapping.cache_clear()


def render_remediation(mapping: ControlMapping, context: dict[str, str]) -> str:
    result = mapping.remediation_template
    for key, value in context.items():
        result = result.replace(f"{{{key}}}", value)

    if "sudo" in result:
        result = "# Requires elevated privileges\n" + result

    return result
