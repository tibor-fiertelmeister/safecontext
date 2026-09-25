from safecontext.detectors import redact_secrets


def test_redacts_password():
    raw = "password=SuperSecret123"

    result = redact_secrets(raw)

    assert "SuperSecret123" not in result
    assert result == "password=[SECRET_REDACTED]"


def test_redacts_api_key():
    raw = "api_key=synthetic-demo-key-123"

    result = redact_secrets(raw)

    assert "synthetic-demo-key-123" not in result
    assert result == "api_key=[SECRET_REDACTED]"


def test_redacts_access_token():
    raw = "access_token=synthetic-access-token"

    result = redact_secrets(raw)

    assert "synthetic-access-token" not in result
    assert result == "access_token=[SECRET_REDACTED]"


def test_redacts_bearer_token():
    raw = "Authorization: Bearer synthetic.token.value"

    result = redact_secrets(raw)

    assert "synthetic.token.value" not in result
    assert result == "Authorization: [SECRET_REDACTED]"
