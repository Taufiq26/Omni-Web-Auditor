import pytest
from src.core import engagement as eng_mod
from src.core.engagement import Engagement, CHK_PASS, CHK_FAIL, CHK_TODO, CHK_NA
from src.core.autofill import autofill, sources_ran_from_coverage
from src.core.models import Finding
from src.core.coverage import coverage_entry, STATUS_TESTED, STATUS_SKIPPED
from src.checklist.loader import load_checklist


@pytest.fixture(autouse=True)
def _tmp(tmp_path, monkeypatch):
    monkeypatch.setattr(eng_mod, "ENGAGEMENTS_DIR", str(tmp_path / "e"))


def _finding(wstg, sev="High"):
    return Finding(vulnerability="V", severity=sev, location="l", evidence="e",
                   remediation="r", wstg_ids=(wstg,))


def test_sources_ran_from_coverage():
    cov = [
        coverage_entry("Security headers", STATUS_TESTED, "x"),
        coverage_entry("Adapter: nuclei", STATUS_TESTED, "x"),
        coverage_entry("Adapter: zap", STATUS_SKIPPED, "no image"),
    ]
    assert sources_ran_from_coverage(cov) == {"native", "nuclei"}


def test_autofill_fail_on_related_finding():
    eng = Engagement(name="e1")
    items = load_checklist()
    autofill(eng, items, [_finding("WSTG-CONF-07")], {"native"})
    assert eng.item_states["WSTG-CONF-07"]["status"] == CHK_FAIL


def test_autofill_pass_when_source_ran_no_finding():
    eng = Engagement(name="e2")
    items = load_checklist()
    autofill(eng, items, [], {"native"})
    # WSTG-CONF-07 sources include native -> pass
    assert eng.item_states["WSTG-CONF-07"]["status"] == CHK_PASS


def test_autofill_todo_when_source_not_run():
    eng = Engagement(name="e3")
    items = load_checklist()
    autofill(eng, items, [], {"nuclei"})  # native tidak jalan
    # WSTG-CRYP-01 sources: testssl,native -> tak ada yg jalan -> tetap todo
    assert eng.item_states["WSTG-CRYP-01"]["status"] == CHK_TODO


def test_autofill_respects_manual():
    eng = Engagement(name="e4")
    items = load_checklist()
    eng.ensure_items(items)
    eng.set_item("WSTG-CONF-07", CHK_NA, note="tidak relevan", auto=False)
    autofill(eng, items, [_finding("WSTG-CONF-07")], {"native"})
    # penilaian manual NA tidak ditimpa auto
    assert eng.item_states["WSTG-CONF-07"]["status"] == CHK_NA
