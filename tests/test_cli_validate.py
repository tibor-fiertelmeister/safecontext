from pathlib import Path

import pytest

from safecontext.cli import main


def test_validate_cli_returns_success_for_safe_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    input_file = tmp_path / "safe.log"
    input_file.write_text(
        "EMAIL_AB12CD34 connected to HOST_1234ABCD from IP_ABCDEF12",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "sys.argv",
        ["safecontext", "validate", str(input_file)],
    )

    main()

    output = capsys.readouterr().out
    assert "Status: SAFE TO SHARE" in output


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
