# SafeContext

**Privacy-first protection for sensitive data in LLM workflows.**

[![SafeContext Tests](https://github.com/tibor-fiertelmeister/safecontext/actions/workflows/tests.yml/badge.svg)](https://github.com/tibor-fiertelmeister/safecontext/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-experimental-orange)

SafeContext is an experimental security tool that creates a local privacy
boundary between sensitive operational data and external or local LLMs.

It detects sensitive information, pseudonymizes identifiers that may need
to be restored later, irreversibly redacts secrets, and validates the
result before the protected content is allowed to leave the local trust
boundary.

```text
Sensitive Input
      |
      v
+-----------------------+
|   Local Inspection    |
+-----------------------+
      |
      v
+-----------------------+
| Pseudonymization      |
| + Secret Redaction    |
+-----------------------+
      |
      v
+-----------------------+
|     Privacy Gate      |
|  validate before use  |
+-----------------------+
      |
      v
 Sanitized Context
      |
      v
 External / Local LLM
      |
      v
 Sanitized Response
      |
      v
+-----------------------+
|   Local Rehydration   |
+-----------------------+
      |
      v
 Final Local Output
```

## Why SafeContext?

LLMs can be extremely useful for analyzing security logs, incidents,
configuration data, vulnerability findings, and operational reports.

The problem is that this data can contain information that should not be
unnecessarily exposed to an external AI service.

Examples include:

- email addresses and usernames
- internal hostnames and domains
- IP addresses
- customer, account, tenant, user, and session identifiers
- infrastructure-specific identifiers
- passwords
- API keys
- access and refresh tokens
- bearer tokens
- JWTs
- other environment-specific information

SafeContext reduces that exposure before the data reaches the model.

The goal is not simply to remove information. The goal is to preserve
enough structure for useful analysis while minimizing disclosure of the
original environment.

## Example

Sensitive input:

```text
alice@example.com connected to prod-db-01.internal
from 10.20.30.40 customer_id=CUST-12345
password=ExampleSecretValue
```

SafeContext can transform it into a representation similar to:

```text
EMAIL_562D450E connected to HOST_7B71BA02
from IP_D5E06542 customer_id=CUSTOMER_ID_F4B57E0E
password=[SECRET_REDACTED]
```

The LLM can still reason about relationships between entities without
receiving the original identifiers.

After analysis, pseudonymized identifiers can be restored locally.

Secrets cannot.

---

## Core security model

SafeContext separates sensitive values into two categories.

### Reversible identifiers

Values that may be required again after LLM processing are replaced with
stable pseudonyms.

Examples:

```text
alice@example.com       -> EMAIL_562D450E
prod-db-01.internal     -> HOST_7B71BA02
10.20.30.40             -> IP_D5E06542
CUST-12345              -> CUSTOMER_ID_F4B57E0E
```

The mapping between the original value and pseudonym remains inside the
local trust boundary.

### Irreversible secrets

Credentials and authentication material should never be sent to the LLM
and should not be recoverable through the mapping vault.

Examples:

```text
password=...              -> password=[SECRET_REDACTED]
api_key=...               -> api_key=[SECRET_REDACTED]
Authorization: Bearer ... -> Authorization: Bearer [SECRET_REDACTED]
JWT                       -> [SECRET_REDACTED]
```

This distinction is fundamental to the SafeContext design:

> **Identifiers may be pseudonymized. Secrets must be removed.**

---

## Privacy Gate

Pseudonymization alone is not enough.

Before protected content is allowed to cross the local trust boundary,
SafeContext can validate it using a **Privacy Gate**.

```text
Raw input
   |
   | validate
   v
 BLOCKED
   |
   | protect locally
   v
Protected input
   |
   | validate
   v
 ALLOWED
   |
   v
LLM
```

The intended security property is **fail closed**:

> If SafeContext still detects raw sensitive information, external
> processing should not continue.

This creates a separate validation layer instead of assuming that the
protection stage worked correctly.

---

## CLI workflow

### Inspect

Inspect input for sensitive entities before processing:

```bash
safecontext inspect incident.log
```

This can be used to understand what SafeContext detects without modifying
the source data.

### Protect

Create an LLM-safe representation:

```bash
safecontext protect incident.log
```

SafeContext pseudonymizes supported identifiers, redacts detected secrets,
and creates a local mapping for reversible values.

### Validate

Check whether content is safe to cross the privacy boundary:

```bash
safecontext validate incident.protected.log
```

Unsafe content causes validation to fail.

This makes the command suitable for scripts, CI/CD workflows, or future
LLM integration pipelines where processing must stop if privacy checks
fail.

### Restore

After an LLM has processed the protected representation:

```bash
safecontext restore analysis.md -m .incident.safecontext-map.json
```

SafeContext restores known pseudonyms using the local mapping.

Irreversibly redacted secrets remain redacted.

---

## End-to-end workflow

The current implementation supports the following security flow:

```text
1. Inspect raw input
           |
           v
2. Privacy Gate blocks raw sensitive content
           |
           v
3. Protect locally
           |
           +--> pseudonymize identifiers
           |
           +--> redact secrets
           |
           v
4. Validate protected representation
           |
           v
5. Send only sanitized context to the LLM
           |
           v
6. Receive sanitized response
           |
           v
7. Restore pseudonymized identifiers locally
```

The repository contains a GitHub Actions demonstration of this complete
flow.

The demo verifies that:

- raw sensitive input is rejected by the Privacy Gate
- identifiers are pseudonymized
- secrets are removed
- protected content passes validation
- an LLM response can be simulated using only protected data
- original identifiers can be restored locally
- redacted secrets are never restored

---

## Current detection capabilities

SafeContext currently includes deterministic detection for several
classes of sensitive information.

### Structured identifiers

- email addresses
- IPv4 addresses
- internal-style hostnames

### Context-aware identifiers

SafeContext can also use surrounding field names to identify values whose
format alone may not indicate that they are sensitive.

Current examples include:

- `customer_id`
- `user_id`
- `account_id`
- `tenant_id`
- `session_id`

### Secrets

Current secret detection includes:

- passwords
- API keys
- access tokens
- refresh tokens
- bearer tokens
- JWTs

Detection is intentionally deterministic and explainable at this stage of
the project.

---

## Design principles

### Local-first

Raw sensitive data should be processed before it crosses the local trust
boundary.

### Data minimization

Only the information required for analysis should be exposed to an LLM.

### Reversible pseudonymization

Identifiers can remain consistent during analysis and can later be
restored locally.

### Irreversible secret redaction

Credentials and authentication material must not be recoverable from the
LLM-visible representation.

### Fail closed

If privacy validation detects unsafe content, external processing should
stop.

### Provider independent

The protection layer is intentionally independent from any specific LLM
provider.

### Explainable detection

Security transformations should be understandable, testable, and
auditable.

---

## Testing

SafeContext includes automated tests covering the protection pipeline,
including:

- deterministic pseudonym generation
- secret redaction
- bearer-token handling
- JWT redaction
- identifier restoration
- contextual identifier handling
- Privacy Gate validation
- CLI validation behavior
- end-to-end protection and restoration properties

Tests run automatically through GitHub Actions.

```bash
pytest -v
```

---

## Security architecture

SafeContext currently follows this trust boundary:

```text
                LOCAL TRUST BOUNDARY

 Sensitive Data
       |
       v
 +-------------+
 | SafeContext |
 +-------------+
       |
       +------> Local Mapping Vault
       |        (sensitive)
       |
       v
 Privacy Gate
       |
       | sanitized content only
       |
-------+--------------------------------
       |
       v
 External LLM / AI Service
```

The external model should never require access to the pseudonym mapping.

This keeps re-identification capability on the trusted side of the
boundary.

---

## Threat model

The project includes an evolving threat model under:

```text
docs/
```

Areas considered include:

- accidental disclosure of identifiers
- credential leakage
- incomplete detection
- mapping exposure
- unsafe outbound content
- incorrect restoration
- trust-boundary violations

SafeContext should be treated as one privacy control in a broader secure
AI architecture rather than as a replacement for organizational data
governance or provider-side security controls.

---

## Project status

> **Experimental / active development**

SafeContext is currently a security engineering and research project.

It should **not** yet be relied upon as a guarantee that arbitrary
production data has been completely sanitized.

The current implementation establishes the core architecture:

**Inspect → Protect → Validate → Process → Restore**

Future work may include:

- configurable detection policies
- additional contextual identifiers
- improved secret detection
- entropy and format-based detection
- encrypted local mapping storage
- structured JSON/log processing
- audit-friendly transformation reports
- integration patterns for LLM workflows
- security-event enrichment after privacy protection

---

## Security note

SafeContext intentionally keeps the mapping vault separate from
LLM-visible content.

Mapping files may contain sensitive original identifiers and must be
protected accordingly.

Do not upload real mapping files, credentials, or production-sensitive
test data to the repository.

---

## License

SafeContext is released under the MIT License.
