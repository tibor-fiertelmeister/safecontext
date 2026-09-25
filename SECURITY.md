# SafeContext Security

## Security model

SafeContext is designed to process sensitive input on a trusted local system
before protected content crosses an LLM or other external processing boundary.

The following data should remain inside the trusted environment:

- original sensitive input
- pseudonym mapping files
- organization-specific sensitive policy configuration
- restored output containing original identifiers

Secrets are intended to be irreversibly redacted rather than stored for later
restoration.

## Important limitations

SafeContext is experimental software.

Detection is rule- and policy-based. A successful validation result means that
the configured/current detectors did not identify unprotected sensitive
content; it is not proof that the content contains no sensitive information.

Do not use GitHub Actions or public issue content for real confidential company
logs, credentials, mappings, or policies.

## Reporting a vulnerability

Please do not disclose real credentials, confidential logs, customer data, or
other sensitive material in a public GitHub issue.

When a private security reporting channel is enabled for this repository, use
that channel for vulnerability reports.
