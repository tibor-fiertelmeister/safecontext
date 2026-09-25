from safecontext.core import protect_text
from safecontext.mapping import MappingVault
from safecontext.validate import format_validation_report, validate_text


def test_validate_blocks_raw_sensitive_content():
    raw = (
        "alice@example.com connected to prod-db-01.internal "
        "from 10.20.30.40 customer_id=CUST-12345"
    )

    result = validate_text(raw)

    assert result.safe is False
    assert result.counts["EMAIL"] == 1
    assert result.counts["HOST"] == 1
    assert result.counts["IP"] == 1
    assert result.counts["CUSTOMER_ID"] == 1


def test_validate_blocks_raw_secret():
    secret = "".join(("SC", "_VALIDATE_", "987"))
    raw = f"password={secret}"

    result = validate_text(raw)

    assert result.safe is False
    assert result.counts["SECRET"] == 1


def test_validate_accepts_protected_content():
    secret = "".join(("SC", "_VALIDATE_", "987"))
    raw = (
        "alice@example.com connected to prod-db-01.internal "
        f"from 10.20.30.40 customer_id=CUST-12345 password={secret}"
    )
    vault = MappingVault(salt="validation-salt")

    protected = protect_text(raw, vault)
    result = validate_text(protected, vault=vault)

    assert result.safe is True
    assert result.counts == {}


def test_validate_accepts_redaction_marker():
    result = validate_text("password=[SECRET_REDACTED]")

    assert result.safe is True
    assert result.counts == {}


def test_validate_accepts_contextual_pseudonym():
    vault = MappingVault(salt="validation-salt")
    token = vault.pseudonym_for("CUSTOMER_ID", "CUST-12345")
    result = validate_text(f"customer_id={token}", vault=vault)

    assert result.safe is True
    assert result.counts == {}


def test_validate_blocks_unverified_pseudonym_even_if_format_looks_right():
    assert not validate_text("customer_id=CUSTOMER_ID_DEADBEEF").safe
    assert not validate_text(
        "customer_id=CUSTOMER_ID_DEADBEEF", vault=MappingVault()
    ).safe
    assert not validate_text("EMAIL_DEADBEEF").safe


def test_validate_still_blocks_fake_contextual_value():
    result = validate_text("customer_id=CUSTOMER_ID_NOTSAFE")

    assert result.safe is False
    assert result.counts["CUSTOMER_ID"] == 1


def test_validation_report_does_not_expose_sensitive_values():
    raw = "alice@example.com from 10.20.30.40"
    result = validate_text(raw)

    report = format_validation_report(result)

    assert "Status: BLOCKED" in report
    assert "EMAIL: 1" in report
    assert "IP: 1" in report
    assert "alice@example.com" not in report
    assert "10.20.30.40" not in report


def test_safe_validation_report():
    result = validate_text("No sensitive values here.")

    report = format_validation_report(result)

    assert result.safe is True
    assert "Status: NO DETECTED LEAKS" in report
    assert "not a guarantee of safe sharing" in report
