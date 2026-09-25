from safecontext.core import protect_text, restore_text
from safecontext.mapping import MappingVault


def test_round_trip_restores_identifiers_and_not_secrets():
    secret_value = "SyntheticPasswordValue987"
    raw = (
        "alice@example.com connected to prod-db-01.internal "
        f"from 10.20.30.40 password={secret_value}"
    )
    vault = MappingVault(salt="test-salt")

    protected = protect_text(raw, vault)

    assert "alice@example.com" not in protected
    assert "prod-db-01.internal" not in protected
    assert "10.20.30.40" not in protected
    assert secret_value not in protected
    assert "password=[SECRET_REDACTED]" in protected

    restored = restore_text(protected, vault)

    assert "alice@example.com" in restored
    assert "prod-db-01.internal" in restored
    assert "10.20.30.40" in restored
    assert secret_value not in restored
    assert "password=[SECRET_REDACTED]" in restored


def test_same_entity_gets_same_pseudonym():
    vault = MappingVault(salt="test-salt")
    raw = "10.20.30.40 failed. Later 10.20.30.40 succeeded."

    protected = protect_text(raw, vault)
    tokens = [
        word.strip(".")
        for word in protected.split()
        if word.startswith("IP_")
    ]

    assert len(tokens) == 2
    assert tokens[0] == tokens[1]


def test_context_identifier_round_trip():
    vault = MappingVault(salt="test-salt")
    raw = "customer_id=CUST-12345"

    protected = protect_text(raw, vault)

    assert "CUST-12345" not in protected
    assert "CUSTOMER_ID_" in protected

    restored = restore_text(protected, vault)

    assert restored == raw
