from safecontext.mapping import MappingVault


def test_pseudonyms_are_stable_inside_vault():
    vault = MappingVault(salt="fixed")
    first = vault.pseudonym_for("EMAIL", "alice@example.com")
    second = vault.pseudonym_for("EMAIL", "alice@example.com")

    assert first == second
    assert vault.reverse[first] == "alice@example.com"
