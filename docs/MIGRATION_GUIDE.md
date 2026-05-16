# Migration Guide

## Upgrading from v0.4.0-rc1

Follow these steps to upgrade safely to `v1.0.0` in production environments.

1. **Fetch and checkout the GA tag**

```bash
git fetch --tags
git checkout v1.0.0
```

2. **Reinstall runtime dependencies**

```bash
pip install -r requirements.txt
```

3. **Refresh environment configuration**

```bash
cp .env.example .env
```

Re-apply environment-specific values after copying:
- `SHIELDEYE_DB_URL`
- `SHIELDEYE_REDIS_URL`
- `GRC_WEBHOOK_URL` / `SHIELDEYE_GRC_WEBHOOK_URL` (if used)

4. **Verify Phase 5 controls are present**

- `ENABLE_POLICY_CACHE`
- `SHIELDEYE_ENABLE_REALTIME_MONITORING`
- `SHIELDEYE_ALERT_WINDOW_SECONDS`

5. **Run validation and smoke checks**

```bash
pytest tests/ -v
python -m backend.cli.advanced health
python -m backend.cli.advanced scan https://example.com --save-db
python -m backend.cli.advanced history --limit 5
```

6. **Roll out gradually**

- Enable observability first (`SHIELDEYE_ENABLE_PROMETHEUS_EXPORT`, `SHIELDEYE_ENABLE_OPENTELEMETRY`).
- Enable optional enterprise workflows (`SHIELDEYE_ENABLE_INTERACTIVE_REMEDIATION`, `ENABLE_GRC_EXPORT`) after baseline health is stable.

## Breaking Changes

- None.

## New Features

### Phase 5 additions

- **Policy cache controls:** `ENABLE_POLICY_CACHE` reduces repeated policy parse/validation overhead in policy execution paths.
- **Redis-backed alert/coordination store:** `SHIELDEYE_REDIS_URL` supports distributed idempotency, queue coordination, and real-time alert state tracking.
- **Type hygiene hardening:** stricter configuration/schema validation paths reduce runtime drift and deployment-time surprises.

## Troubleshooting

### 1) Startup fails with database URL validation

- Symptom: configuration error referencing `SHIELDEYE_DB_URL`.
- Fix: verify DSN format is valid PostgreSQL URI and credentials are non-empty.

### 2) Real-time monitoring shows no events

- Symptom: monitoring endpoints load but no live alert activity.
- Fix: enable `SHIELDEYE_ENABLE_REALTIME_MONITORING=true` and verify `SHIELDEYE_ALERT_WINDOW_SECONDS` is set to a practical value (for example `300`).

### 3) Policy validation throughput is slower than expected

- Symptom: repeated policy checks take longer after upgrade.
- Fix: ensure `ENABLE_POLICY_CACHE=true` and confirm Redis connectivity if distributed workers are used.

### 4) GRC export payload not generated

- Symptom: JSON report has no `grc_export` section.
- Fix: set `ENABLE_GRC_EXPORT=true` (or `SHIELDEYE_ENABLE_GRC_EXPORT=true`), then verify `GRC_PLATFORM` and related credentials.

### 5) Telemetry missing in observability stack

- Symptom: no Prometheus metrics or OTEL traces after rollout.
- Fix: enable `SHIELDEYE_ENABLE_PROMETHEUS_EXPORT` / `SHIELDEYE_ENABLE_OPENTELEMETRY`, then validate network routing to your scrape/collector endpoints.

# Impact: A dedicated migration runbook lowers upgrade risk and shortens time-to-production for v1.0.0 adoption.
