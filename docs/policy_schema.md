# Policy Schema (MVP: YAML/Rego)

This reference defines the operator-facing policy format for MVP compliance authoring.

## Minimal Valid Policy (YAML)

The example below uses the same naming and field conventions as built-in templates such as `quick_gdpr` and `security_headers`.

```yaml
policy_id: quick_gdpr
name: Quick GDPR Compliance
description: Fast GDPR compliance check for websites
standards:
  - GDPR
mode: Quick/Safe
max_pages: 10
max_depth: 2
timeout: 10
verify_ssl: true
allow_insecure: false
checks_enabled:
  ssl: true
  headers: true
  cookies: true
  privacy_policy: true
  cookie_consent: true
tags:
  - gdpr
  - privacy
  - quick
controls:
  - id: GDPR-3.1.1
    check_name: privacy_policy
    severity: high
  - id: GDPR-3.2.1
    check_name: cookie_consent
    severity: medium
```

A second minimal pattern for a focused profile:

```yaml
policy_id: security_headers
name: Security Headers Check
description: Focus on HTTP security headers
standards: []
mode: Quick/Safe
max_pages: 5
max_depth: 1
timeout: 10
verify_ssl: true
allow_insecure: false
checks_enabled:
  headers: true
  ssl: true
tags:
  - headers
  - security
  - quick
```

## Control ID Mapping

Use this convention for deterministic control linking:

`{standard}-{section}.{item}` -> `check_name`

Examples:

- `CIS-4.1.3` -> `auditd_rule_present`
- `GDPR-3.2.1` -> `cookie_consent`
- `PCI-DSS-4.2` -> `secure_transmission`
- `ISO27001-8.2.1` -> `access_control`

Mapping guidance:

1. Keep control IDs in canonical standard format.
2. Keep `check_name` lowercase snake_case.
3. Reuse existing check names from `checks_enabled` keys when possible.
4. Prefer one control ID per check; document exceptions explicitly in policy notes.

## Validation Rules

| Field | Required For | Type | Example |
|---|---|---|---|
| `policy_id` | YAML policies | string | `quick_gdpr` |
| `name` | YAML policies | string | `Quick GDPR Compliance` |
| `description` | YAML policies | string | `Fast GDPR compliance check for websites` |
| `standards` | YAML policies | list[string] | `["GDPR"]` |
| `mode` | YAML policies | enum string | `Quick/Safe` |
| `max_pages` | YAML policies | integer | `10` |
| `max_depth` | YAML policies | integer | `2` |
| `timeout` | YAML policies | integer | `10` |
| `verify_ssl` | YAML policies | boolean | `true` |
| `allow_insecure` | YAML policies (optional) | boolean | `false` |
| `checks_enabled` | YAML policies | map[string, boolean] | `{ ssl: true, headers: true }` |
| `tags` | YAML policies (optional) | list[string] | `["gdpr", "quick"]` |
| `controls[].id` | YAML policies (optional) | string | `CIS-4.1.3` |
| `controls[].check_name` | YAML policies (optional) | string | `auditd_rule_present` |
| `controls[].severity` | YAML policies (optional) | enum string | `high` |
| `package` | Rego policies | string | `shieldeye.policy.quick_gdpr` |
| `default allow` | Rego policies | boolean rule | `default allow = false` |

Common expected values:

- `mode`: `Quick/Safe`, `Aggressive/Full`, `Deep/Thorough`
- `standards`: `GDPR`, `PCI-DSS`, `ISO 27001`, `HIPAA`

## Rego Policy Stub

Minimal OPA/Rego skeleton for advanced users:

```rego
package shieldeye.policy.quick_gdpr

default allow = false

default deny = []

allow {
  input.mode == "Quick/Safe"
  input.verify_ssl == true
  input.checks_enabled.privacy_policy
  input.checks_enabled.cookie_consent
}

deny[msg] {
  not input.verify_ssl
  msg := "TLS verification must remain enabled for this policy"
}
```
