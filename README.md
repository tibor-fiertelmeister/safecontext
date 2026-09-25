# SafeContext

**A privacy-first local protection layer for working with sensitive data and LLMs.**

SafeContext is an experimental security tool for protecting sensitive logs, reports, and structured text before they are shared with an external or local Large Language Model (LLM).

Instead of sending raw identifiers, infrastructure details, or credentials directly to an AI system, SafeContext processes the data first:

- reversible identifiers are replaced with deterministic pseudonyms;
- secrets and credentials are irreversibly redacted;
- a Privacy Gate validates that protected content is safe to share;
- LLM responses can be processed locally to restore the original operational context.

The goal is simple:

> **Keep sensitive context local while preserving enough structure for useful AI-assisted analysis.**

---

## How it works

```text
                  LOCAL TRUST BOUNDARY
┌─────────────────────────────────────────────────────┐
│                                                     │
│  Raw Input                                          │
│      │                                              │
│      ▼                                              │
│   INSPECT                                           │
│      │                                              │
│      ▼                                              │
│   PROTECT                                           │
│      │                                              │
│      ├── Identifiers ──► Pseudonymize               │
│      │                                              │
│      └── Secrets ──────► Irreversible Redaction     │
│      │                                              │
│      ▼                                              │
│   PRIVACY GATE                                      │
│      │                                              │
│      ├── Unsafe ───────► BLOCK                      │
│      │                                              │
│      └── Safe ─────────► Allow                      │
│                                                     │
└──────────────────────┬──────────────────────────────┘
                       │
                       │ Protected content only
                       ▼
                 External / Local LLM
                       │
                       │ Protected response
                       ▼
┌─────────────────────────────────────────────────────┐
│                  LOCAL TRUST BOUNDARY               │
│                                                     │
│   RESTORE                                           │
│      │                                              │
│      ├── Pseudonyms ──► Original identifiers        │
│      │                                              │
│      └── Secrets ─────► Remain redacted             │
│                                                     │
│   Final locally rehydrated result                   │
│                                                     │
└─────────────────────────────────────────────────────┘
```

Raw sensitive data and pseudonym mappings are intended to remain inside the local trust boundary.

---

## Example

Raw input:

```text
alice@example.com connected to prod-db-01.internal
from 10.20.30.40 customer_id=CUST-12345
password=example-secret-value
```

SafeContext protection produces a representation similar to:

```text
EMAIL_562D450E connected to HOST_7B71BA02
from IP_D5E06542 customer_id=CUSTOMER_ID_F4B57E0E
password=[SECRET_REDACTED]
```

The protected version preserves relationships between entities without exposing their original values.

After an LLM processes the protected representation, SafeContext can restore the reversible identifiers locally:

```text
alice@example.com connected to prod-db-01.internal
from 10.20.30.40 customer_id=CUST-12345
password=[SECRET_REDACTED]
```

The password is never restored because secrets are intentionally excluded from the reversible mapping.

---

## Privacy model

SafeContext treats sensitive information differently depending on its type.

### Reversible pseudonymization

Identifiers that may be required later for operational context are replaced with deterministic pseudonyms.

Currently supported examples include:

- email addresses
- IPv4 addresses
- internal hostnames
- customer IDs
- user IDs
- account IDs
- tenant IDs
- session IDs

Example:

```text
10.20.30.40
```

becomes:

```text
IP_D5E06542
```

The original value is stored only in the local mapping vault so it can later be restored.

### Irreversible secret redaction

Credentials and authentication material should not be recoverable from LLM-visible content.

SafeContext currently detects examples including:

- passwords
- API keys
- access tokens
- refresh tokens
- bearer tokens
- JWTs

Example:

```text
password=example-secret-value
```

becomes:

```text
password=[SECRET_REDACTED]
```

Secrets are not added to the reversible mapping.

---

## Privacy Gate

Protection and validation are separate security controls.

SafeContext does not assume that content is safe merely because the protection step completed.

The Privacy Gate performs a second inspection before content is considered suitable for external processing.

```text
Raw sensitive content
        │
        ▼
   Privacy Gate
        │
        ▼
     BLOCKED
```

After successful protection:

```text
Protected content
        │
        ▼
   Privacy Gate
        │
        ▼
  SAFE TO SHARE
```

Already protected SafeContext pseudonyms and `[SECRET_REDACTED]` markers are recognized as protected representations rather than raw sensitive values.

This creates a fail-closed boundary between local processing and external AI processing.

---

## CLI

### Inspect

Inspect a file for sensitive entities without modifying it:

```bash
safecontext inspect incident.log
```

This can be used to understand what SafeContext detects before protection.

### Protect

Protect a text or log file:

```bash
safecontext protect incident.log
```

SafeContext creates a protected representation and a local pseudonym mapping.

Explicit output locations can also be supplied:

```bash
safecontext protect incident.log \
  --output incident.protected.log \
  --mapping .incident.safecontext-map.json
```

The mapping contains original identifiers and must be treated as sensitive.

### Validate

Validate content before sharing it externally:

```bash
safecontext validate incident.protected.log
```

Safe content returns a successful exit status.

If raw sensitive content is detected, validation fails with a non-zero exit status so the Privacy Gate can also be used in automated workflows.

### Restore

Restore reversible identifiers locally:

```bash
safecontext restore analysis.md \
  --mapping .incident.safecontext-map.json \
  --output analysis.restored.md
```

Pseudonymized identifiers are restored.

Irreversibly redacted secrets remain:

```text
[SECRET_REDACTED]
```

---

## End-to-end Privacy Gate demo

The repository contains a GitHub Actions workflow demonstrating the complete SafeContext lifecycle using synthetic data only.

The demo verifies:

```text
Synthetic sensitive input
        │
        ▼
Privacy Gate
        │
        └── BLOCKED
        │
        ▼
Inspect
        │
        ▼
Protect
        │
        ▼
Privacy Gate
        │
        └── SAFE TO SHARE
        │
        ▼
Simulated LLM response
        │
        ▼
Local restore
        │
        ▼
Security verification
```

The workflow checks that:

- raw sensitive input is blocked;
- identifiers are pseudonymized before simulated LLM exposure;
- secrets are irreversibly redacted;
- protected content passes the Privacy Gate;
- reversible identifiers can be restored locally;
- secrets cannot be restored;
- secrets are not stored in the local pseudonym mapping.

The workflow can be run manually from:

```text
Actions → SafeContext Privacy Gate Demo → Run workflow
```

---

## Automated testing

SafeContext includes automated tests covering the current privacy pipeline, including:

- deterministic pseudonym generation;
- password redaction;
- API key redaction;
- access token redaction;
- bearer token redaction;
- JWT redaction;
- reversible identifier round trips;
- contextual identifier handling;
- mapping isolation;
- Privacy Gate validation;
- CLI validation behavior;
- protected-value recognition;
- secret non-restoration.

The current test suite contains **25 automated tests**.

GitHub Actions runs the test suite automatically on repository changes.

---

## Security design principles

SafeContext follows several core principles.

### Local first

Raw sensitive data should be processed before it reaches an external AI service.

### Data minimization

Only information required for useful analysis should leave the local trust boundary.

### Reversible identifiers

Operational identifiers can be restored when they are required in the final result.

### Irreversible secrets

Credentials and authentication material should never be recoverable from LLM-visible data.

### Fail closed

If privacy validation detects unprotected sensitive content, external processing should be blocked.

### Defense in depth

Detection, transformation, and validation are separate stages rather than a single sanitization operation.

### Provider independent

The protection layer is independent of any specific LLM provider.

### Traceable

Transformations should be deterministic, understandable, and testable.

---

## Repository structure

```text
safecontext/
├── .github/
│   └── workflows/
│       ├── demo.yml
│       ├── inspect.yml
│       ├── privacy-gate-demo.yml
│       ├── roundtrip.yml
│       └── tests.yml
│
├── docs/
│
├── examples/
│   └── privacy-gate-demo.log
│
├── src/
│   └── safecontext/
│       ├── cli.py
│       ├── core.py
│       ├── detectors.py
│       ├── inspect.py
│       ├── mapping.py
│       └── validate.py
│
├── tests/
│
├── .gitignore
├── LICENSE
├── pyproject.toml
└── README.md
```

---

## Current project status

> **Experimental / early development**

SafeContext is currently a security engineering, research, and portfolio project.

The core privacy pipeline is operational and covered by automated tests, but SafeContext should **not currently be treated as a guarantee that arbitrary production data has been fully sanitized**.

Detection is currently deterministic and primarily pattern- and context-based.

Real-world sensitive data can appear in formats that are difficult or impossible to identify reliably using deterministic rules alone.

For this reason, SafeContext should currently be considered an additional privacy control rather than a replacement for organizational data handling policies, DLP systems, access controls, or human review.

---

## Current limitations

The current implementation has several intentional limitations:

- detection coverage is not exhaustive;
- custom organization-specific identifiers may require additional rules;
- mapping storage is local JSON and is not yet encrypted at rest;
- detection currently focuses primarily on text and log-style input;
- semantic sensitive-data classification is not yet implemented;
- the project does not currently send content to an LLM itself;
- the GitHub demo simulates the LLM processing stage.

These limitations are explicit parts of the current threat model.

---

## Roadmap

Potential future development includes:

- configurable organization-specific detection policies;
- custom identifier patterns;
- additional contextual detectors;
- entropy and format-based secret detection;
- encrypted local mapping storage;
- structured JSON and security-event processing;
- richer Privacy Gate policies;
- confidence-based detection;
- audit-friendly transformation reports;
- local DLP-style inspection;
- security-event enrichment;
- optional MITRE ATT&CK technique mapping after privacy protection;
- integrations with local and external LLM workflows.

A key architectural principle is that security enrichment and AI analysis should happen **after** privacy protection whenever possible.

---

## Threat model

SafeContext maintains a separate threat model under:

```text
docs/
```

The central trust assumption is:

> **Raw sensitive data and reversible pseudonym mappings stay local. External systems receive only protected representations.**

---

## License

SafeContext is released under the MIT License.
