# ShieldEye ComplianceScan — Integration Guide

This guide explains how to connect ShieldEye ComplianceScan with the ShieldEye ecosystem (Core and SurfaceScan) to import external scan findings and correlate them to compliance controls.

---

## Data Flow Overview

```
┌─────────────┐      ┌──────────────────────────┐      ┌──────────────────┐      ┌─────────────┐
│   Target    │─────▶│  ComplianceScan          │─────▶│  CoreClient      │─────▶│  Compliance │
│  (URL/IP)   │      │  (Orchestrator + Policy  │      │  SurfaceScan     │      │  Report     │
└─────────────┘      │   Engine)                │      │  Client          │      │  (JSON /    │
                     └──────────────────────────┘      └──────────────────┘      │  SARIF)     │
                              │                           │                      └─────────────┘
                              │                           │
                              ▼                           ▼
                     ┌──────────────────┐        ┌──────────────────┐
                     │  policy/         │        │  integrations/   │
                     │  validator.py    │        │  core_client.py  │
                     │  benchmark/      │        │  surfacescan_    │
                     │  engine.py       │        │  client.py       │
                     └──────────────────┘        └──────────────────┘
```

**Flow explanation:**
1. **Target** — The URL, IP, or asset being evaluated.
2. **ComplianceScan** — The main orchestrator (`benchmark/engine.py`) loads policies, executes controls, and collects raw findings.
3. **Core / SurfaceScan** — Optional external data sources. `CoreClient` imports deep scan results from a ShieldEye-Core instance. `SurfaceScanClient` imports surface-level findings (SSL, headers, cookies, privacy, tracking) from ShieldEye-SurfaceScan.
4. **Report** — Findings are merged, correlated to controls, and exported as JSON or SARIF via `backend/reporting/exporters.py`.

---

## Core Integration

The `CoreClient` (`integrations/core_client.py`) provides a typed, SSRF-safe HTTP client for pulling scan results from a ShieldEye-Core instance.

### Configuration

```python
from integrations.core_client import CoreClient

client = CoreClient(
    base_url="https://core.internal.example.com",
    api_key="shieldeye_...",          # Optional: Bearer token auth  # nosec B107 # pragma: allowlist secret
    timeout=30,                       # Request timeout in seconds
    allow_internal=False,             # Set True only for internal Core instances
)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `base_url` | `str` | — | Root URL of the Core API. Automatically normalized to `https://` if no scheme is provided. |
| `api_key` | `str \| None` | `None` | Bearer token sent in the `Authorization` header. |
| `timeout` | `int` | `30` | HTTP request timeout (seconds). |
| `allow_internal` | `bool` | `False` | When `False`, blocks `localhost`, `127.0.0.1`, and private IP ranges to prevent SSRF. |

### Key Methods

- `get_scan_results(scan_id: str) -> CoreScanResult | None`  
  Fetches a single scan by ID. Returns `None` on 404, timeout, or schema mismatch.

- `list_recent_scans(limit: int = 50) -> list[CoreScanResult]`  
  Lists recently completed scans. Skips scans with a non-completed status.

---

## SurfaceScan Integration

The `SurfaceScanClient` (`integrations/surfacescan_client.py`) imports surface-level security findings and maps them to compliance controls via a lightweight heuristic.

### Configuration

```python
from integrations.surfacescan_client import SurfaceScanClient

client = SurfaceScanClient(
    base_url="https://surfacescan.internal.example.com",
    api_key="shieldeye_...",  # nosec B107 # pragma: allowlist secret
    timeout=30,
    allow_internal=False,
)
```

Parameters match `CoreClient` exactly (same SSRF-safe validation logic).

### Key Methods

- `get_findings(target_url: str) -> list[SurfaceFinding]`  
  Retrieves findings for a specific target URL. Returns an empty list on 404 (no findings yet).

- `correlate_to_control(finding: SurfaceFinding, control_id: str) -> bool`  
  Heuristic matcher that decides whether a surface finding maps to a given compliance control.

### Correlation Heuristic

`correlate_to_control()` uses a lightweight rule-based mapping (Phase 2 MVP). It is deterministic and requires no external ML model:

| Finding Category | Matched Control Prefix | Rationale |
|------------------|------------------------|-----------|
| `ssl` | `CIS-4.*` | CIS Control 4 covers secure configuration of assets, including TLS settings. |
| `headers` | `CIS-5.*` | CIS Control 5 focuses on account and access management; security headers (CSP, HSTS, X-Frame-Options) directly support this. |
| `cookies` | `CIS-5.*` | Session management and cookie flags (Secure, HttpOnly, SameSite) align with access-control objectives. |
| `privacy` | `GDPR-*` | Privacy-policy detection and cookie-consent mechanisms map to GDPR data-protection requirements. |
| `tracking` | `GDPR-*` | Third-party and analytics tracking visibility supports GDPR accountability and consent obligations. |

> **Note:** Phase 3 will introduce an optional ML-based correlation layer that scores semantic similarity between finding descriptions and control descriptions, improving accuracy beyond prefix matching.

---

## Troubleshooting

| Symptom | Likely Cause | Hint |
|---------|--------------|------|
| `404 from Core API` | The `scan_id` does not exist on the targeted Core instance. | Verify `scan_id` exists in the Core instance’s database or UI. |
| `Timeout from Core API` | Network latency, firewall rules, or Core instance overload. | Check network connectivity, increase `timeout`, or verify the instance is healthy (`GET /health` on Core). |
| `ValueError: Localhost and private IP addresses are not allowed` | `allow_internal=False` (default) and the `base_url` resolves to a private IP. | If the Core/SurfaceScan instance is genuinely internal, set `allow_internal=True`. Never expose this flag to untrusted user input. |
| `Invalid JSON` response | API version mismatch between ComplianceScan and Core/SurfaceScan. | Verify both services are on compatible versions. Check `Content-Type` header on the response. |
| `Unexpected schema` validation error | The upstream API returned a field shape not expected by `CoreScanResult` or `SurfaceFinding`. | Review the Pydantic validation error in logs and compare the payload against the model definitions in `core_client.py` / `surfacescan_client.py`. |
| Empty findings list from SurfaceScan | Target has not been scanned yet, or the URL encoding does not match SurfaceScan’s index. | Ensure the exact URL was previously scanned by SurfaceScan. Check URL encoding (`quote(target_url, safe="")`). |

---

# Impact: Documented data flow and integration contracts reduce onboarding friction, prevent misconfiguration of SSRF-sensitive clients, and provide a stable contract for Phase 3 observability hooks.
