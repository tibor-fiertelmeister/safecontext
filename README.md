# SafeContext

**Privacy-first local protection for sensitive data in LLM workflows.**

SafeContext is an experimental security CLI that creates a local privacy
boundary between sensitive operational data and external or local LLMs.

Raw identifiers are pseudonymized locally, credentials and secrets are
irreversibly redacted, and a privacy validation gate can block content that
still contains detectable sensitive values.

> **Project status:** Alpha / experimental. SafeContext is a portfolio and
> research project and should not yet be treated as a guarantee that arbitrary
> production data has been fully sanitized.

## What SafeContext does

```text
Sensitive file
     |
     v
Local inspection
     |
     v
Pseudonymization + secret redaction
     |
     v
Privacy validation gate
     |
     v
Protected file  --------->  LLM
                               |
                               v
                         protected response
                               |
                               v
                    local identifier restoration
```

The local mapping is part of the trust boundary. It must not be sent to an
external LLM or committed to source control.

## Quick start

SafeContext currently requires Python 3.12 or newer.

### Install from a cloned repository

```bash
git clone https://github.com/tibor-fiertelmeister/safecontext.git
cd safecontext
python -m pip install .
```

Check the CLI:

```bash
safecontext --help
```

### Run the synthetic quickstart

For a first look at the complete privacy flow without using real confidential
data:

```bash
safecontext quickstart
```

The command creates synthetic operational data, detects example identifiers,
protects them locally, irreversibly redacts a synthetic secret, and verifies
that the original demo values are absent from the protected output.

### Inspect a file

```bash
safecontext inspect incident.log
```

This reports detected sensitive entity categories without intentionally
printing their original values.

### Protect a file

```bash
safecontext protect incident.log
```

SafeContext creates a protected file and a local mapping file.

Example transformation:

```text
alice@example.com        -> EMAIL_A8173C42
10.20.30.40              -> IP_92AE410B
prod-db-01.internal      -> HOST_192FA812
password=example-value   -> password=[SECRET_REDACTED]
```

### Validate before crossing the privacy boundary

```bash
safecontext validate incident.protected.log
```

The intended behavior is fail-closed:

```text
SAFE
```

or a blocked result if detectable unprotected sensitive content remains.

### Restore local context

After an LLM returns content containing SafeContext pseudonyms:

```bash
safecontext restore analysis.md -m .incident.safecontext-map.json
```

Selected identifiers are restored locally. Redacted secrets are not
recoverable.

## Custom detection policies

Environment-specific identifiers can be described with a local policy rather
than hard-coded into the application. This is useful for organization-specific
customer, ticket, asset, tenant, or similar identifiers.

Keep organization-specific policy files local when they reveal internal naming
conventions or other sensitive information.

## Trust boundary

SafeContext is designed around one rule:

> **Raw sensitive data and pseudonym mappings stay local.**

GitHub Actions in this repository use synthetic test/demo data. They are for
development and demonstration, not for uploading real corporate logs.

## Commands

```text
safecontext quickstart
safecontext inspect <file>
safecontext protect <file>
safecontext validate <file>
safecontext restore <file> -m <mapping-file>
```

Run:

```bash
safecontext --help
```

for the CLI available in the installed version.

## Development

Create an environment, install development dependencies, and run tests:

```bash
python -m pip install -e ".[dev]"
pytest -v
```

Build distributable artifacts:

```bash
python -m build
```

Artifacts are created under `dist/`.

## Security limitations

SafeContext uses deterministic detection rules and configurable policies.
No detector can guarantee discovery of every possible sensitive value.

Before production adoption, organizations should perform their own security
review, define appropriate policies, test representative data, protect local
mapping files, and establish controls around the LLM boundary.

See `SECURITY.md` and the project documentation for additional guidance.

## Roadmap

- broader configurable detection policies
- stronger privacy validation
- packaging and release hardening
- policy schema/versioning
- security-event enrichment after privacy protection
- privacy-preserving security analysis workflows

## License

MIT
