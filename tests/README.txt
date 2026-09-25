SafeContext diagnostic test package

Upload:
  test_diagnostics.py -> tests/test_diagnostics.py

Do not replace the existing production files for this diagnostic run.

Expected total:
  Existing 7 tests + 6 diagnostic tests = 13 tests.

The diagnostic tests isolate:
- direct password redaction
- password through protect_text
- password after restore_text
- direct Bearer redaction
- Bearer through protect_text
- mapping-vault separation (identifiers stored, secrets never stored)

Suggested commit:
  test: add isolated redaction pipeline diagnostics
