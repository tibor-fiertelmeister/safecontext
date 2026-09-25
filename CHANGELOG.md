# Changelog

All notable project changes should be documented here.

## [Unreleased]

### Planned

- expanded policy documentation
- additional privacy validation tests
- policy schema/versioning

## [0.1.2] - Privacy gate hardening

### Fixed

- complete quoted secret values, including spaces, are redacted
- validation uses the same custom policy and verifies contextual pseudonyms
  against the local mapping
- policy changes or missing mappings cannot produce a successful CLI privacy gate
- protection validates detected values before writing the protected output
- mapping files are created with private permissions on POSIX systems
- custom policy is available through the inspect, protect and validate CLI
- the current-source installation workflow no longer tests the older release

The detector remains rule-based and cannot guarantee that arbitrary input
contains no sensitive data. The mapping is not encrypted.

## [0.1.1] - Quickstart

### Added

- `safecontext quickstart` synthetic first-run demonstration
- end-to-end quickstart privacy verification
- automated quickstart test coverage
- first-user quickstart documentation

### Changed

- improved first-run experience for new SafeContext users
- package version updated to 0.1.1

## [0.1.0] - Initial alpha

### Added

- local identifier pseudonymization
- irreversible secret redaction
- privacy inspection
- privacy validation gate
- local identifier restoration
- configurable custom detection policies
- automated tests and synthetic demonstration workflows
