"""Diagnostic tests for SafeContext's secret-redaction pipeline.

These tests intentionally use structural checks and dynamically assembled
fixtures so CI log masking cannot obscure which stage failed.
"""

from safecontext.core import protect_text, restore_text
from safecontext.detectors import redact_secrets
from safecontext.mapping import MappingVault


def _password_fixture() -> tuple[str, str]:
    # Assemble the label at runtime so the full key/value fixture is not a
    # literal secret-looking string in the source or traceback.
    key = "".join(("pass", "word"))
    value = "".join(("SC", "_DIAG_", "VALUE_", "987"))
    return f"{key}={value}", value


def _bearer_fixture() -> tuple[str, str]:
    scheme = "".join(("Bear", "er"))
    token = ".".join(("scdiag", "token", "987"))
    return f"Authorization: {scheme} {token}", token


def test_diagnostic_password_redactor_stage():
    raw, secret = _password_fixture()
    result = redact_secrets(raw)

    assert secret not in result
    assert "[SECRET_REDACTED]" in result
    assert result.startswith("password=")


def test_diagnostic_password_survives_protection_as_redacted_marker():
    credential, secret = _password_fixture()
    raw = (
        "alice@example.com connected to prod-db-01.internal "
        f"from 10.20.30.40 {credential}"
    )
    vault = MappingVault(salt="diagnostic-salt")

    protected = protect_text(raw, vault)

    assert secret not in protected
    assert "[SECRET_REDACTED]" in protected
    assert "password=" in protected
    assert "alice@example.com" not in protected
    assert "prod-db-01.internal" not in protected
    assert "10.20.30.40" not in protected


def test_diagnostic_password_remains_redacted_after_restore():
    credential, secret = _password_fixture()
    raw = (
        "alice@example.com connected to prod-db-01.internal "
        f"from 10.20.30.40 {credential}"
    )
    vault = MappingVault(salt="diagnostic-salt")

    protected = protect_text(raw, vault)
    restored = restore_text(protected, vault)

    assert "alice@example.com" in restored
    assert "prod-db-01.internal" in restored
    assert "10.20.30.40" in restored
    assert secret not in restored
    assert "[SECRET_REDACTED]" in restored
    assert "password=" in restored


def test_diagnostic_bearer_redactor_stage():
    raw, token = _bearer_fixture()
    result = redact_secrets(raw)

    assert token not in result
    assert "[SECRET_REDACTED]" in result
    assert result.startswith("Authorization:")
    assert "Bearer" in result


def test_diagnostic_bearer_through_protect_text():
    bearer, token = _bearer_fixture()
    raw = f"request to prod-api.internal from 10.20.30.40 with {bearer}"
    vault = MappingVault(salt="diagnostic-salt")

    protected = protect_text(raw, vault)

    assert token not in protected
    assert "[SECRET_REDACTED]" in protected
    assert "Authorization:" in protected
    assert "Bearer" in protected
    assert "prod-api.internal" not in protected
    assert "10.20.30.40" not in protected


def test_diagnostic_mapping_contains_identifiers_but_not_secrets():
    credential, secret = _password_fixture()
    bearer, token = _bearer_fixture()
    raw = (
        "alice@example.com prod-db-01.internal 10.20.30.40 "
        f"{credential} {bearer}"
    )
    vault = MappingVault(salt="diagnostic-salt")

    protect_text(raw, vault)

    mapped_originals = set(vault.reverse.values())

    assert "alice@example.com" in mapped_originals
    assert "prod-db-01.internal" in mapped_originals
    assert "10.20.30.40" in mapped_originals
    assert secret not in mapped_originals
    assert token not in mapped_originals
