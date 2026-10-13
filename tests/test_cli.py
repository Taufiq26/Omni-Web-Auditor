"""Tes handler CLI `audit` dengan engine di-mock (tanpa jaringan/Docker)."""

import pytest

from src.cli import app
from src.core import engagement as eng_mod
from src.core.engagement import Engagement, CHK_PASS
from src.core.models import Finding, CoverageEntry, STATUS_FIXED


@pytest.fixture(autouse=True)
def _tmp_env(tmp_path, monkeypatch):
    monkeypatch.setattr(eng_mod, "ENGAGEMENTS_DIR", str(tmp_path / "engagements"))
    monkeypatch.chdir(tmp_path)


class _FakeEngine:
    result_findings = [
        Finding(vulnerability="Missing Security Header: CSP", severity="Low",
                location="https://x.com", evidence="e", remediation="r",
                wstg_ids=("WSTG-CONF-07",)),
    ]

    def __init__(self, config):
        self.config = config

    def run(self):
        cov = [CoverageEntry("Security headers", "TESTED", "ok")]
        return list(self.result_findings), cov


def _init(name="demo", target="https://x.com", extra=None):
    app.main(["init", name, "--target", target] + (extra or []))


def test_init_creates_engagement():
    _init()
    assert Engagement.exists("demo")
    eng = Engagement.load("demo")
    assert eng.target == "https://x.com"
    assert eng.scope == ["x.com"]


def test_init_duplicate_fails():
    _init()
    with pytest.raises(SystemExit):
        _init()


def test_run_populates_findings_and_autofill(monkeypatch):
    _init()
    monkeypatch.setattr(app, "AuditEngine", _FakeEngine)
    app.main(["run", "demo", "--no-adapters"])
    eng = Engagement.load("demo")
    assert len(eng.findings) == 1
    # CONF-07 harus FAIL karena ada temuan terkait
    assert eng.item_states["WSTG-CONF-07"]["status"] == "fail"


def test_intrusive_blocked_in_production(monkeypatch):
    _init(extra=["--environment", "production", "--intrusive"])
    with pytest.raises(SystemExit):
        app.main(["run", "demo", "--allow-intrusive"])


def test_mark_with_evidence(tmp_path):
    _init()
    ev = tmp_path / "shot.png"
    ev.write_bytes(b"\x89PNG x")
    app.main(["mark", "WSTG-ATHN-03", "--name", "demo", "--status", "pass",
              "--note", "ok", "--evidence", str(ev)])
    eng = Engagement.load("demo")
    st = eng.item_states["WSTG-ATHN-03"]
    assert st["status"] == CHK_PASS
    assert len(st["evidence"]) == 1
    assert st["evidence"][0]["sha256"]


def test_finding_status_update(monkeypatch):
    _init()
    monkeypatch.setattr(app, "AuditEngine", _FakeEngine)
    app.main(["run", "demo", "--no-adapters"])
    app.main(["finding", "0", "--name", "demo", "--status", STATUS_FIXED])
    eng = Engagement.load("demo")
    assert eng.findings[0]["status"] == STATUS_FIXED


def test_signoff_records(monkeypatch):
    _init()
    app.main(["signoff", "demo", "--name-signer", "Tester"])
    eng = Engagement.load("demo")
    assert eng.signoff["name"] == "Tester"


def test_report_generates(monkeypatch):
    _init()
    monkeypatch.setattr(app, "AuditEngine", _FakeEngine)
    app.main(["run", "demo", "--no-adapters"])
    out = "rpt.pdf"
    app.main(["report", "demo", "--output", out])
    import os
    assert os.path.exists(out)


def test_resolve_name_none_fails():
    with pytest.raises(SystemExit):
        app.main(["verdict"])  # belum ada engagement


def test_checklist_runs(capsys, monkeypatch):
    _init()
    app.main(["checklist", "demo"])
    out = capsys.readouterr().out
    assert "WSTG-CONF-07" in out
