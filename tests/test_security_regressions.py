"""Regression checks for observed privacy-boundary failures."""

import os
import stat

import pytest

from safecontext.core import protect_file, protect_text
from safecontext.cli import main
from safecontext.mapping import MappingVault
from safecontext.policy import load_policy
from safecontext.validate import validate_text


def test_custom_policy_is_used_by_protection_and_validation(tmp_path):
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(
        '{"identifiers":[{"name":"EMPLOYEE_ID","fields":["employee_id"]}],'
        '"secrets":[{"name":"PRIVATE_VALUE","fields":["private_value"]}]}',
        encoding="utf-8",
    )
    policy = load_policy(policy_file)
    raw = 'employee_id=EMP-99182 private_value="two secret words"'
    vault = MappingVault()
    protected = protect_text(raw, vault, policy)
    assert "EMP-99182" not in protected
    assert "two secret words" not in protected
    assert "secret words" not in protected
    assert validate_text(protected, policy, vault).safe
    assert not validate_text(protected, policy).safe
    assert not validate_text(protected, vault=vault).safe
    assert not validate_text("employee_id=EMP-99182", policy, vault).safe


def test_mapping_is_private_and_names_with_underscores_survive_reload(tmp_path):
    vault = MappingVault(salt="fixed")
    token = vault.pseudonym_for("EMPLOYEE_ID", "EMP-99182")
    path = tmp_path / "map.json"
    vault.save(path)
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    loaded = MappingVault.load(path)
    assert loaded.pseudonym_for("EMPLOYEE_ID", "EMP-99182") == token


def test_protect_refuses_to_overwrite_raw_input(tmp_path):
    raw = tmp_path / "raw.txt"
    raw.write_text("alice@example.com", encoding="utf-8")
    with pytest.raises(ValueError):
        protect_file(raw, raw, tmp_path / "map.json")
    assert raw.read_text(encoding="utf-8") == "alice@example.com"


def test_protect_file_rejects_detected_leak_without_writing(tmp_path, monkeypatch):
    raw = tmp_path / "raw.txt"
    output = tmp_path / "protected.txt"
    mapping = tmp_path / "map.json"
    raw.write_text("customer_id=CUST-12345", encoding="utf-8")
    monkeypatch.setattr("safecontext.core.protect_text", lambda *args, **kwargs: "customer_id=CUST-12345")
    with pytest.raises(ValueError, match="validation failed"):
        protect_file(raw, output, mapping)
    assert not output.exists()
    assert not mapping.exists()


def test_cli_policy_round_trip_and_verified_gate(tmp_path, monkeypatch, capsys):
    policy = tmp_path / "policy.json"
    policy.write_text(
        '{"identifiers":[{"name":"EMPLOYEE_ID","fields":["employee_id"]}]}',
        encoding="utf-8",
    )
    raw = tmp_path / "incident.log"
    raw.write_text("employee_id=EMP-99182", encoding="utf-8")
    output = tmp_path / "incident.protected.log"
    mapping = tmp_path / ".incident.safecontext-map.json"

    monkeypatch.setattr(
        "sys.argv", ["safecontext", "protect", str(raw), "-p", str(policy)]
    )
    main()
    assert "EMP-99182" not in output.read_text(encoding="utf-8")

    monkeypatch.setattr(
        "sys.argv", ["safecontext", "validate", str(output),
                     "-p", str(policy), "-m", str(mapping)]
    )
    main()
    assert "NO DETECTED LEAKS" in capsys.readouterr().out

    monkeypatch.setattr(
        "sys.argv", ["safecontext", "validate", str(output), "-p", str(policy)]
    )
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1
