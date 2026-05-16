# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-05-16

### Added
- Stable GA release packaging and operational baseline for production deployments across scanner, policy, integration, reporting, and monitoring workflows.
- Policy-as-code validation and control mapping pipeline for CIS/PCI-DSS/SOC2/GDPR (`policy/validator.py`, `benchmark/engine.py`).
- Async, idempotent benchmark orchestration with scheduler-safe execution paths (`benchmark/orchestrator.py`, `backend/integrations/scheduler.py`).
- Typed integration layer for ShieldEye-Core and SurfaceScan with correlation pipeline support (`integrations/core_client.py`, `integrations/surfacescan_client.py`, `integrations/correlation.py`).
- Enterprise reporting and export surface including JSON/SARIF output, remediation snippets, and GRC payload formatters (`reporting/generator.py`, `reporting/grc_exporters.py`, `reporting/grc_payload_formatters.py`).
- Monitoring and observability routes plus production telemetry hooks (`api/routes/monitoring.py`, `backend/utils/observability.py`).

### Changed
- Hardened configuration model and environment-override behavior for production-safe defaults and backward-compatible flag parsing (`backend/utils/config.py`).
- Standardized release documentation for deployment, integration, and observability operations (`README.md`, `docs/INTEGRATION_GUIDE.md`, `docs/OBSERVABILITY_GUIDE.md`).
- Improved benchmarking/reporting runtime efficiency with cache-aware and Redis-backed operational paths (`policy/validator.py`, `backend/utils/resilience.py`).

### Fixed
- Resolved idempotency and retry edge cases in scan/benchmark execution flows to reduce duplicate processing under retries (`benchmark/orchestrator.py`, `backend/integrations/scheduler.py`).
- Tightened type hygiene and validation paths to prevent config/schema drift at runtime (`backend/utils/config.py`, `policy/validator.py`).
- Improved resilience behavior for upstream dependency failures via rate limiting, timeout controls, and fallback correlation behavior (`backend/utils/resilience.py`, `integrations/correlation.py`).

### Security
- Preserved secure-by-default transport posture with explicit insecure-target opt-in controls (`backend/utils/config.py`).
- Maintained SSRF-safe integration client behavior and stricter upstream URL handling (`integrations/core_client.py`, `integrations/surfacescan_client.py`).
- Strengthened operational auditability with feature-flag snapshots and release-grade configuration guidance (`reporting/generator.py`, `.env.example`).

## [0.1.0-alpha] - 2026-05-09

### Added
- Initial release documentation and operational baseline for `v0.1.0-alpha`.
- Feature-flag controls for benchmark execution and remediation snippet inclusion.
- Compliance-ready environment template aligned with `SHIELDEYE_*` configuration keys.

### Fixed
- P0: API contract hardening across documented and exposed scan endpoints.
- P0: Secure TLS defaults to prevent unintended insecure target handling.
- P1: Configuration validation at startup for required and typed runtime settings.
- P1: Idempotency behavior for repeated scan-processing flows.
- P1: Test import reliability issues impacting local and CI execution.
- P1: Coverage gate enforcement for quality baseline protection.

### Security
- Enforced secure-by-default transport behavior (`ALLOW_INSECURE_TARGETS=false` by default).
- Strengthened configuration safety checks for database connectivity and startup integrity.
- Closed alpha-stage release blockers tied to API and TLS risk classes.

## [0.2.0-beta] - 2026-05-09

### Added
- Policy-as-code parser with YAML/Rego support and `control_id` validation (`policy/validator.py`).
- Compliance control mapping for CIS, PCI-DSS, SOC2, and GDPR registries with remediation templates (`benchmark/engine.py`).
- Async benchmark orchestrator with idempotency guards and retry-aware scheduling (`benchmark/orchestrator.py`).
- Typed integration clients for ShieldEye-Core and ShieldEye-SurfaceScan with SSRF-safe URL validation (`integrations/core_client.py`, `integrations/surfacescan_client.py`).
- Heuristic finding→control correlation (`correlate_to_control`) for surface scan data (`integrations/surfacescan_client.py`).
- JSON and SARIF export formats plus copy-paste remediation snippets in reports (`backend/reporting/exporters.py`).
- Integration guide documenting data flow, client configuration, and troubleshooting (`docs/INTEGRATION_GUIDE.md`).
- Phase 2 capability documentation and expanded API surface reference in `README.md`.

### Fixed
- P0: SSRF prevention in integration clients via private-IP blocking and strict URL validation.
- P0: Idempotency race conditions in scan creation flow via deterministic hash keys.
- P1: Timeout handling and retry logic for upstream Core/SurfaceScan API failures.
- P1: Schema validation mismatches when importing external scan results.

### Security
- SSRF validation in `CoreClient` and `SurfaceScanClient` (`allow_internal` flag, private-IP rejection).
- Secret redaction in database connection strings via `.env.example` comments and CI scanning.
- Secure-by-default transport behavior preserved (`ALLOW_INSECURE_TARGETS=false`).

## [0.3.0-rc1] - 2026-05-10

### Added
- Resilience utilities for per-target rate limiting and circuit-breaker management with Redis-aware coordination (`backend/utils/resilience.py`).
- Observability primitives with `MetricsCollector`, Prometheus export toggle, and `trace_span`-based trace context hooks (`backend/utils/observability.py`).
- Advanced finding-to-control correlation via `CorrelationEngine` with heuristic and optional ML backend support (`integrations/correlation.py`).
- Release documentation updates: Phase 3 capability/deployment guidance in `README.md`, Phase 3 flags in `.env.example`, and the new observability runbook (`docs/OBSERVABILITY_GUIDE.md`).

### Fixed
- Hardened fallback behavior so correlation remains deterministic when ML dependencies are unavailable or confidence is below threshold (`integrations/correlation.py`).
- Improved operational guidance for tuning rate limits, circuit-breaker thresholds, and trace/metrics rollout to reduce misconfiguration risk in production (`backend/utils/resilience.py`, `backend/utils/observability.py`).

### Security
- Reinforced production-safe defaults by documenting controlled activation paths for metrics export, OpenTelemetry tracing, and ML correlation.
- Preserved secure transport posture and auditable runtime controls while adding observability and resilience release documentation.

[0.2.0-beta]: https://github.com/exiv703/ShieldEye_ComplianceScan/compare/v0.1.0-alpha...v0.2.0-beta

[0.3.0-rc1]: https://github.com/exiv703/ShieldEye_ComplianceScan/compare/v0.2.0-beta...v0.3.0-rc1

[0.4.0-rc1]: https://github.com/exiv703/ShieldEye_ComplianceScan/compare/v0.3.0-rc1...v0.4.0-rc1

[1.0.0]: https://github.com/exiv703/ShieldEye_ComplianceScan/compare/v0.4.0-rc1...v1.0.0

[Unreleased]: https://github.com/exiv703/ShieldEye_ComplianceScan/compare/v1.0.0...HEAD

# Impact: Stable v1.0.0 release notes provide auditable module-level change tracking and safer production upgrade planning.
