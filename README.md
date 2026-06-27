<div align="center">

# 🛡️ ShieldEye ComplianceScan

**Web compliance and vulnerability scanner**

*GDPR • PCI-DSS • ISO 27001, with a GTK4 desktop UI, a REST API, and JSON/SARIF reporting*

[![License: MIT](https://img.shields.io/badge/License-MIT-1F6FEB?style=for-the-badge&labelColor=22272E)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.10--3.13-1F6FEB?logo=python&logoColor=white&style=for-the-badge&labelColor=22272E)](https://www.python.org/)
[![GTK4](https://img.shields.io/badge/GTK-4.0-1F6FEB?logo=gtk&logoColor=white&style=for-the-badge&labelColor=22272E)](https://www.gtk.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-REST_API-1F6FEB?logo=fastapi&logoColor=white&style=for-the-badge&labelColor=22272E)](https://fastapi.tiangolo.com/)

[Features](#features) • [Quick Start](#quick-start) • [Screenshots](#screenshots) • [Architecture](#architecture) • [API](#api) • [Contributing](#contributing)

---

![ShieldEye ComplianceScan Dashboard](docs/screenshots/dashboard.png)

</div>

---

## What is ShieldEye ComplianceScan?

ComplianceScan checks a web target against common security baselines and maps
the findings onto compliance standards. It inspects TLS configuration, security
headers, and cookie flags, then evaluates the result against GDPR, PCI-DSS, and
ISO 27001 control sets and produces a report with CVSS v3.1-scored findings.

You can drive it three ways: a GTK4 desktop app for interactive use, a CLI for
local and scripted runs, and a FastAPI REST service for integration. Results are
persisted to SQLite and can be exported as JSON, SARIF, CSV, XML, Markdown, or
PDF.

It's meant for the recurring "is this site configured sanely, and where does it
sit against the standards we care about" check, not a substitute for a full
audit or a manual pentest. HIPAA mapping exists but is partial.

> ⚠️ **Authorized use only.** Only scan systems you own or have explicit written
> permission to test.

---

## Features

<table>
<tr>
<td width="50%">

### Security scanning
- **TLS/SSL:** certificate validity, cipher strength, protocol versions
- **Security headers:** CSP, HSTS, X-Frame-Options, CORS
- **Cookies:** `Secure`, `HttpOnly`, `SameSite`
- **Tech detection:** outdated libraries and frameworks
- **Forms:** autocomplete and HTTPS-enforcement checks

</td>
<td width="50%">

### Compliance mapping
- **GDPR:** privacy-policy detection, cookie consent
- **PCI-DSS:** payment-form and password handling
- **ISO 27001:** `security.txt`, incident-response signals
- **HIPAA:** partial healthcare-data checks
- **Multi-standard:** several standards in one pass

</td>
</tr>
<tr>
<td width="50%">

### Interfaces
- **GTK4 desktop app** with a dark theme
- **CLI** for local and scripted scans
- **FastAPI REST API** with OpenAPI/Swagger docs
- **Dashboard + history** with filtering

</td>
<td width="50%">

### Scoring & reporting
- **CVSS v3.1** severity scoring
- **PDF reports** via wkhtmltopdf
- **Exports:** JSON, SARIF, CSV, XML, Markdown
- **SQLite persistence** with full scan history

</td>
</tr>
</table>

---

## Screenshots

<div align="center">

| Dashboard | New Scan | History |
|:---------:|:--------:|:-------:|
| ![Dashboard](docs/screenshots/dashboard.png) | ![New Scan](docs/screenshots/new-scan.png) | ![History](docs/screenshots/history.png) |
| *Compliance overview and metrics* | *Configure and launch a scan* | *Scan audit trail with filtering* |

</div>

---

## Architecture

A modular Python backend shared by three frontends (GTK, CLI, REST):

```
┌──────────────────────────────────────────────────────────────┐
│           GTK4 GUI  •  CLI  •  FastAPI REST API               │
└─────────────────────────────┬────────────────────────────────┘
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                      Backend Core                             │
│              Scanner • Analyzer • Reporter                    │
└───────┬─────────────────────┬─────────────────────┬──────────┘
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│   Scanner     │    │   Analyzer    │    │   Reporter    │
│  (requests)   │    │ (Compliance)  │    │ (PDF/SARIF…)  │
└───────────────┘    └───────────────┘    └───────────────┘
        └──────────┬──────────┴─────────────────────┘
                   ▼
        ┌─────────────────────────────┐
        │        SQLite Database       │
        │  Scans • Findings • History  │
        └─────────────────────────────┘
```

### Tech Stack

| Layer | Technology |
|-------|------------|
| **GUI** | GTK4 + libadwaita, PyGObject |
| **API** | FastAPI, Uvicorn |
| **Scanning** | requests, BeautifulSoup4 |
| **Reporting** | wkhtmltopdf (PDF), SARIF/CSV/XML/Markdown exporters |
| **Storage** | SQLite |

---

## Quick Start

### Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.10–3.13 | |
| GTK4 + libadwaita | 4.0+ | system package, with PyGObject |
| wkhtmltopdf | recent | only for PDF reports |
| Linux | - | tested on Arch, Fedora/RHEL |

### 1. Install system dependencies

GTK and PyGObject come from your distro, not pip:

```bash
# Arch
sudo pacman -S python-gobject gtk4 libadwaita wkhtmltopdf

# Fedora / RHEL
sudo dnf install python3-gobject gtk4 libadwaita wkhtmltopdf
```

### 2. Get the code and install Python deps

```bash
git clone https://github.com/exiv703/ShieldEye_ComplianceScan.git
cd ShieldEye_ComplianceScan
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Or use the interactive launcher, which handles dependency install for you:

```bash
./run.sh
```

### 3. Launch

```bash
./run.sh             # interactive menu
python main_gtk.py   # GUI directly
```

---

## CLI

```bash
# Run a scan and save it to the database
python -m backend.cli.advanced scan https://example.com --save-db

# View recent scans
python -m backend.cli.advanced history --limit 10

# Compare two scans
python -m backend.cli.advanced compare <scan-id-a> <scan-id-b>

# Health and database stats
python -m backend.cli.advanced health
python -m backend.cli.advanced stats
```

---

## Configuration

Paths are overridable via environment variables:

```bash
export SHIELDEYE_DB_PATH="$HOME/.shieldeye/scans.db"
export SHIELDEYE_LOG_DIR="$HOME/.shieldeye/logs"
export SHIELDEYE_REPORTS_DIR="$HOME/.shieldeye/reports"
```

A few capabilities are gated behind flags (defaults are safe):

| Flag | Default | Description |
|------|---------|-------------|
| `COMPLIANCE_BENCHMARKS_ENABLED` | `true` | CIS/PCI-DSS/SOC2 benchmark execution |
| `SHIELDEYE_ALLOW_INSECURE_TARGETS` | `false` | Permit scanning targets with invalid TLS (internal use) |
| `ENABLE_REMEDIATION_SNIPPETS` | `true` | Include copy-paste fix commands in reports |

Production toggles (Redis-backed rate limiting, Prometheus export, ML
correlation) live in `.env.example` and are documented in
[`docs/MIGRATION_GUIDE.md`](docs/MIGRATION_GUIDE.md). Version history is in
[`CHANGELOG.md`](CHANGELOG.md).

---

## API

The REST API ships with OpenAPI/Swagger docs. Scan and config routes require a
Bearer token; health and template lookups are open.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/scans` | Create and queue a compliance scan |
| `GET` | `/scans` | List recent scans (with filtering) |
| `GET` | `/scans/{id}` | Scan details and findings |
| `DELETE` | `/scans/{id}` | Remove a scan and its findings |
| `GET` | `/scans/{id}/export?format=sarif` | Export results (json, csv, xml, sarif, markdown) |
| `GET` | `/templates` · `/templates/{name}` | Scan templates |
| `POST` | `/schedules` · `GET` `/schedules` | Recurring scan schedules |
| `POST` | `/webhooks/subscribe` · `GET` `/webhooks` | Scan-completion webhooks |
| `GET` | `/stats` | Aggregated scan statistics |
| `GET` | `/health` | Service health and dependency checks |

See [`docs/INTEGRATION_GUIDE.md`](docs/INTEGRATION_GUIDE.md) for the Core /
SurfaceScan data flow.

---

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Tests (113 across scanner, policy, integrations, reporting, …)
pytest tests/ -v
pytest tests/ --cov=backend --cov-report=html
```

Beyond the basics, the backend also carries a policy-as-code engine
(`policy/validator.py`), control-mapping benchmarks (`benchmark/engine.py`),
typed Core/SurfaceScan integration clients (`integrations/`), and optional
resilience/observability hooks (`backend/utils/`). See [`CHANGELOG.md`](CHANGELOG.md)
for what landed when.

---

## Contributing

1. Fork and branch off `main`.
2. Keep changes scoped and add tests for new scanner or compliance logic.
3. Make sure `pytest` passes before opening a PR.

---

## License

MIT - see [LICENSE](LICENSE).

---

## Related Projects

Part of the **ShieldEye** toolkit:

- **[ShieldEye Core](https://github.com/exiv703/ShieldEye-Core)** - network security scanner (Nmap + GTK4)
- **[ShieldEye SurfaceScan](https://github.com/exiv703/ShieldEye-SurfaceScan)** - web attack-surface mapper
- **[ShieldEye NeuralScan](https://github.com/exiv703/ShieldEye-NeuralScan)** - local source-code security scanner
