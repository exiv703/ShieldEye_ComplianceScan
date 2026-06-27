"""Control mapping engine for ShieldEye ComplianceScan.

Translates policy control_ids (e.g. CIS-4.1.3) into executable check definitions
with standard-specific metadata and remediation templates.  This module is the
bridge between high-level policy documents and concrete, platform-aware
compliance checks.
"""

from benchmark.engine import ControlMapping, get_control_mapping, render_remediation
from benchmark.orchestrator import (
    BenchmarkResult,
    execute_benchmark,
    is_execution_idempotent,
)

__all__ = [
    "BenchmarkResult",
    "ControlMapping",
    "execute_benchmark",
    "get_control_mapping",
    "is_execution_idempotent",
    "render_remediation",
]
