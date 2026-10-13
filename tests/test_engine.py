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
