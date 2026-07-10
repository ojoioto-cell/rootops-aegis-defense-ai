from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_all_in_one_check_script_exists_and_is_executable():
    p = ROOT / "scripts" / "aegis_all_in_one_check.sh"
    assert p.exists()
    assert p.stat().st_mode & 0o111
    text = p.read_text()
    for needle in [
        "post_install_competition_check.sh",
        "diagnose_ai_connectivity.sh",
        "self-check",
        "secrets-check",
        "run_ai_duel_demo.sh",
        "generate_proof_report.sh",
        "cleanup-expired",
        "unsafe wildcard",
    ]:
        assert needle in text


def test_installer_calls_all_in_one_check():
    text = (ROOT / "scripts" / "all_in_one_competition_install.sh").read_text()
    assert "aegis_all_in_one_check.sh" in text
    assert "AEGIS_AUTO_RESET_BASELINE=1" in text


def test_version_0214_consistency():
    assert (ROOT / "VERSION").read_text().strip() == "0.3.1"
    assert '__version__ = "0.3.1"' in (ROOT / "src" / "aegis_agent" / "__init__.py").read_text()
    assert 'version = "0.3.1"' in (ROOT / "pyproject.toml").read_text()
    assert 'CENTRAL_VERSION = "0.3.1"' in (ROOT / "src" / "aegis_central" / "server.py").read_text()
