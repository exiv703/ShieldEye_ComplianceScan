# Changelog

All notable changes to this project will be documented in this file.

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

[0.2.0-beta]: https://github.com/exiv703/ShieldEye_ComplianceScan/compare/v0.1.0-alpha...v0.2.0-beta

[Unreleased]: https://github.com/exiv703/ShieldEye_ComplianceScan/compare/v0.2.0-beta...HEAD

# Impact: Versioned change history improves traceability, audit evidence quality, and release governance for compliance-oriented deployments.
