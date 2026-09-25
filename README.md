# SafeContext

**A privacy-first local pseudonymization layer for working with
sensitive data and LLMs.**

SafeContext is an experimental security tool designed to help users work
with potentially sensitive logs, reports, and other structured text
using external LLMs without sending the original identifiers and secrets
to the model.

The core idea is simple:

1.  Sensitive input is processed locally.
2.  Identifiers such as usernames, hostnames, IP addresses, and email
    addresses are replaced with consistent pseudonyms.
3.  Secrets such as passwords, API keys, and authentication tokens are
    removed rather than preserved.
4.  Only the protected representation is provided to the LLM.
5.  The LLM response can be processed locally to restore the original
    context.

``` text
Sensitive Input
      |
      v
Local Detection
      |
      v
Pseudonymization + Secret Redaction
      |
      v
Privacy Validation
      |
      v
Sanitized Context
      |
      v
External or Local LLM
      |
      v
Sanitized Response
      |
      v
Local Rehydration
      |
      v
Final Report
```

## Why SafeContext?

Security logs and operational data often contain information that should
not be unnecessarily exposed to external AI services, including:

-   usernames and email addresses
-   internal hostnames and domains
-   IP addresses
-   infrastructure identifiers
-   filesystem paths
-   API keys and authentication tokens
-   other environment-specific information

SafeContext aims to minimize that exposure while preserving enough
relationships between entities for an LLM to reason about the data.

For example:

``` text
alice@example.com -> USER_A12F
prod-db-01        -> HOST_91BC
10.20.30.40       -> IP_C103
API key           -> [SECRET_REDACTED]
```

The pseudonyms remain consistent within an analysis context, allowing
relationships and event sequences to remain understandable without
exposing the original values.

## Design principles

-   **Local-first** --- raw sensitive data is processed locally.
-   **Data minimization** --- send only what is necessary for analysis.
-   **Reversible pseudonymization** --- selected identifiers can be
    restored locally.
-   **Irreversible secret redaction** --- credentials and secrets should
    never be restored.
-   **Fail closed** --- external processing should be blocked if privacy
    validation fails.
-   **Provider independent** --- the core protection layer should not
    depend on a specific LLM.
-   **Traceable** --- transformations should be understandable and
    auditable.

## Planned workflow

Protect sensitive input:

``` bash
safecontext protect incident.log
```

SafeContext creates a protected representation of the input and stores
the pseudonym mapping locally.

The protected content can then be analyzed using an external or local
LLM.

After receiving the analysis:

``` bash
safecontext restore analysis.md
```

SafeContext restores pseudonymized identifiers using the locally stored
mapping.

Secrets that were irreversibly redacted are never restored.

## Project status

> **Early development / experimental**

SafeContext is currently a portfolio and research project.

It should **not** yet be relied upon to guarantee removal of all
sensitive information from production data.

The initial development focus is:

-   text and log input
-   entity detection
-   deterministic pseudonymization
-   secret detection and redaction
-   local mapping storage
-   privacy validation
-   result rehydration

## Security

SafeContext is being designed around a simple trust boundary:

> **Raw sensitive data and pseudonym mappings stay local.**

External systems should receive only the protected representation.

A formal threat model and security architecture will be maintained as
the project develops.

## License

SafeContext is released under the MIT License.
