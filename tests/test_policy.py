from pathlib import Path

import pytest

from safecontext.core import protect_text, restore_text
from safecontext.mapping import MappingVault
from safecontext.policy import load_policy


def _write_policy(tmp_path: Path) -> Path:
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        """
{
  "identifiers": [
    {"name": "EMPLOYEE_ID", "fields": ["employee_id", "employee_number"]},
    {"name": "CASE_ID", "fields": ["case_id", "case_number"]}
  ],
  "secrets": [
    {"name": "PRIVATE_TOKEN", "fields": ["private_token", "internal_token"]}
  ]
}
""".strip(),
        encoding="utf-8",
    )
    return policy_path


def test_load_custom_policy(tmp_path):
    policy = load_policy(_write_policy(tmp_path))
    assert len(policy.identifiers) == 2
    assert len(policy.secrets) == 1
    assert policy.identifiers[0].name == "EMPLOYEE_ID"
    assert policy.identifiers[0].action == "PSEUDONYMIZE"
    assert policy.secrets[0].name == "PRIVATE_TOKEN"
    assert policy.secrets[0].action == "REDACT"


def test_custom_identifier_is_pseudonymized(tmp_path):
    policy = load_policy(_write_policy(tmp_path))
    vault = MappingVault(salt="policy-test-salt")
    raw = "employee_id=EMP-99182"
    protected = protect_text(raw, vault, policy=policy)
    assert "EMP-99182" not in protected
    assert "employee_id=EMPLOYEE_ID_" in protected


def test_same_custom_identifier_is_stable(tmp_path):
    policy = load_policy(_write_policy(tmp_path))
    vault = MappingVault(salt="policy-test-salt")
    raw = "employee_id=EMP-99182 employee_number=EMP-99182"
    protected = protect_text(raw, vault, policy=policy)
    tokens = [word.split("=", 1)[1] for word in protected.split()]
    assert len(tokens) == 2
    assert tokens[0] == tokens[1]


def test_custom_identifier_can_be_restored(tmp_path):
    policy = load_policy(_write_policy(tmp_path))
    vault = MappingVault(salt="policy-test-salt")
    raw = "case_number=INC-2026-5541"
    protected = protect_text(raw, vault, policy=policy)
    assert "INC-2026-5541" not in protected
    assert "CASE_ID_" in protected
    assert restore_text(protected, vault) == raw


def test_custom_secret_is_irreversibly_redacted(tmp_path):
    policy = load_policy(_write_policy(tmp_path))
    vault = MappingVault(salt="policy-test-salt")
    secret = "SyntheticPrivateValue987"
    raw = f"private_token={secret}"
    protected = protect_text(raw, vault, policy=policy)
    assert secret not in protected
    assert "[SECRET_REDACTED]" in protected
    restored = restore_text(protected, vault)
    assert secret not in restored
    assert "[SECRET_REDACTED]" in restored


def test_builtin_detection_still_works_with_policy(tmp_path):
    policy = load_policy(_write_policy(tmp_path))
    vault = MappingVault(salt="policy-test-salt")
    raw = (
        "alice@example.com "
        "employee_id=EMP-99182 "
        "from 10.20.30.40"
    )
    protected = protect_text(raw, vault, policy=policy)
    assert "alice@example.com" not in protected
    assert "EMP-99182" not in protected
    assert "10.20.30.40" not in protected
    assert "EMAIL_" in protected
    assert "EMPLOYEE_ID_" in protected
    assert "IP_" in protected


def test_invalid_policy_is_rejected(tmp_path):
    policy_path = tmp_path / "invalid-policy.json"
    policy_path.write_text(
        """
{
  "identifiers": [
    {"name": "EMPLOYEE_ID", "fields": []}
  ]
}
""".strip(),
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        load_policy(policy_path)
