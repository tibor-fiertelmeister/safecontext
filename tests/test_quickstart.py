from pathlib import Path

from safecontext.quickstart import run_quickstart


def test_quickstart_creates_safe_protected_output(tmp_path: Path):
    result = run_quickstart(tmp_path)

    raw_path = tmp_path / "safecontext-demo.log"
    protected_path = tmp_path / "safecontext-demo.protected.log"
    mapping_path = tmp_path / ".safecontext-demo.safecontext-map.json"

    assert result == 0
    assert raw_path.exists()
    assert protected_path.exists()
    assert mapping_path.exists()

    protected = protected_path.read_text(encoding="utf-8")

    assert "alice@example.com" not in protected
    assert "prod-db-01.internal" not in protected
    assert "10.20.30.40" not in protected
    assert "SC_DEMO_SECRET_12345" not in protected
    assert "[SECRET_REDACTED]" in protected
    assert "EMAIL_" in protected
    assert "HOST_" in protected
    assert "IP_" in protected
