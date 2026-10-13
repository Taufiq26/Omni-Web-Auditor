"""Tes orkestrasi AuditEngine untuk bagian adapter (tanpa jaringan)."""

from src.core.engine import AuditEngine, AuditConfig
from src.core.scope import Scope
from src.core.coverage import STATUS_SKIPPED
from src.adapters import default_adapters
from src.core.models import SOURCE_NUCLEI, SOURCE_TESTSSL, SOURCE_ZAP, SOURCE_SQLMAP


def test_default_adapters_non_intrusive():
    names = [a.name for a in default_adapters(intrusive=False)]
    assert SOURCE_SQLMAP not in names
    assert {SOURCE_NUCLEI, SOURCE_TESTSSL, SOURCE_ZAP} <= set(names)


def test_default_adapters_intrusive_adds_sqlmap():
    names = [a.name for a in default_adapters(intrusive=True)]
    assert SOURCE_SQLMAP in names


def test_adapters_skipped_when_out_of_scope():
    # Target di luar scope -> adapter dilewati tanpa menjalankan tool apa pun.
    cfg = AuditConfig(
        target="https://evil.com",
        scan_type="full",
        scope=Scope.from_list(["example.com"]),
    )
    engine = AuditEngine(cfg)
    engine._run_adapters()
    statuses = [(c.test, c.status) for c in engine.coverage]
    assert ("Adapter eksternal", STATUS_SKIPPED) in statuses


# --- jalur native (scanner di-fake) ---
class _FakeScanner:
    def __init__(self, *a, **k):
        from src.core.coverage import coverage_entry, STATUS_TESTED
        self.coverage = [coverage_entry("Security headers", STATUS_TESTED, "ok")]

    def run_scan(self, *a, **k):
        from src.core.models import Finding
        return [Finding(vulnerability="V", severity="Low", location="l",
                        evidence="e", remediation="r", wstg_ids=("WSTG-CONF-07",))]


def test_engine_native_path(monkeypatch):
    from src.core import engine as eng
    monkeypatch.setattr(eng, "BasicScanner", _FakeScanner)
    monkeypatch.setattr(eng, "ActiveScanner", _FakeScanner)
    monkeypatch.setattr(eng, "InfraScanner", _FakeScanner)
    cfg = AuditConfig(target="https://x.com", scan_type="full", use_adapters=False)
    findings, coverage = eng.AuditEngine(cfg).run()
    assert len(findings) >= 1
    assert any(c.test == "Security headers" for c in coverage)
