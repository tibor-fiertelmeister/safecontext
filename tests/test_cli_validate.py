from pathlib import Path

import pytest

from safecontext.cli import main
from safecontext.mapping import MappingVault


def test_validate_cli_returns_success_for_safe_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    input_file = tmp_path / "safe.log"
    vault = MappingVault()
    email = vault.pseudonym_for("EMAIL", "alice@example.com")
    input_file.write_text(f"{email} connected safely", encoding="utf-8")
    mapping = tmp_path / "map.json"
    vault.save(mapping)

    monkeypatch.setattr(
        "sys.argv",
        ["safecontext", "validate", str(input_file), "-m", str(mapping)],
    )

    main()

    output = capsys.readouterr().out
    assert "Status: NO DETECTED LEAKS" in output


def test_validate_cli_returns_exit_1_for_unsafe_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    input_file = tmp_path / "unsafe.log"
    input_file.write_text(
        "alice@example.com connected from 10.20.30.40",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "sys.argv",
        ["safecontext", "validate", str(input_file)],
    )

    with pytest.raises(SystemExit) as exc:
        main()

    assert exc.value.code == 1

    output = capsys.readouterr().out
    assert "Status: BLOCKED" in output
    assert "alice@example.com" not in output
    assert "10.20.30.40" not in output
