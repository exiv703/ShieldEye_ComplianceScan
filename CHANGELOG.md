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

[Unreleased]: https://github.com/exiv703/ShieldEye_ComplianceScan/compare/v0.1.0-alpha...HEAD

# Impact: Versioned change history improves traceability, audit evidence quality, and release governance for compliance-oriented deployments.
