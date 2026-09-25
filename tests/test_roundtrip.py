from safecontext.core import protect_text, restore_text
from safecontext.mapping import MappingVault


def test_round_trip_restores_identifiers_and_not_secrets():
    raw = (
        "alice@example.com connected to prod-db-01.internal "
        "from 10.20.30.40 password=SuperSecret123"
    )
    vault = MappingVault(salt="test-salt")

    protected = protect_text(raw, vault)

    assert "alice@example.com" not in protected
    assert "prod-db-01.internal" not in protected
    assert "10.20.30.40" not in protected
    assert "SuperSecret123" not in protected
    assert "[SECRET_REDACTED]" in protected

    restored = restore_text(protected, vault)

    assert "alice@example.com" in restored
    assert "prod-db-01.internal" in restored
    assert "10.20.30.40" in restored
    assert "SuperSecret123" not in restored
    assert "[SECRET_REDACTED]" in restored


def test_same_entity_gets_same_pseudonym():
    vault = MappingVault(salt="test-salt")
    raw = "10.20.30.40 failed. Later 10.20.30.40 succeeded."

    protected = protect_text(raw, vault)
    tokens = [word.strip(".") for word in protected.split() if word.startswith("IP_")]

    assert len(tokens) == 2
    assert tokens[0] == tokens[1]
