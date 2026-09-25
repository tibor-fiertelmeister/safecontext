from safecontext.detectors import redact_secrets


def test_redacts_password():
    secret = "SyntheticPasswordValue987"
    raw = f"password={secret}"
    result = redact_secrets(raw)

    assert secret not in result
    assert result == "password=[SECRET_REDACTED]"


def test_redacts_api_key():
    secret = "synthetic-api-value-987"
    raw = f"api_key={secret}"
    result = redact_secrets(raw)

    assert secret not in result
    assert result == "api_key=[SECRET_REDACTED]"


def test_redacts_access_token():
    secret = "synthetic-access-value-987"
    raw = f"access_token={secret}"
    result = redact_secrets(raw)

    assert secret not in result
    assert result == "access_token=[SECRET_REDACTED]"


def test_redacts_bearer_token():
    token = "synthetic.bearer.value.987"
    raw = f"Authorization: Bearer {token}"
    result = redact_secrets(raw)

    assert token not in result
    assert result == "Authorization: Bearer [SECRET_REDACTED]"


def test_redacts_standalone_jwt():
    jwt = "eyJheader.payload.signature"
    result = redact_secrets(jwt)

    assert jwt not in result
    assert result == "[SECRET_REDACTED]"
