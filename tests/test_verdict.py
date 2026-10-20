import pytest
from src.core import engagement as eng_mod
from src.core.engagement import Engagement, CHK_PASS, CHK_TODO
from src.core.verdict import evaluate, VERDICT_PASS, VERDICT_FAIL, VERDICT_INCOMPLETE
from src.core.models import (
    Finding, SEVERITY_HIGH, SEVERITY_MEDIUM,
    STATUS_FIXED, STATUS_ACCEPTED,
)
from src.checklist.loader import load_checklist


@pytest.fixture(autouse=True)
def _tmp(tmp_path, monkeypatch):
    monkeypatch.setattr(eng_mod, "ENGAGEMENTS_DIR", str(tmp_path / "e"))


def _f(sev, status="open", wstg="WSTG-INPV-05"):
    return Finding(vulnerability="V", severity=sev, location="l", evidence="e",
                   remediation="r", wstg_ids=(wstg,), status=status)


def _all_pass_engagement(items, signed=True):
    eng = Engagement(name="e")
    eng.ensure_items(items)
    for it in items:
        eng.set_item(it.id, CHK_PASS, note="ok", auto=True)  # auto -> tidak wajib bukti
    if signed:
        eng.signoff = {"name": "T", "statement": "s", "signed_at": "now"}
    return eng


def test_fail_on_open_high():
    items = load_checklist()
    eng = _all_pass_engagement(items)
    result = evaluate(eng, items, [_f(SEVERITY_HIGH)])
    assert result.status == VERDICT_FAIL


def test_incomplete_when_item_todo():
    items = load_checklist()
    eng = _all_pass_engagement(items)
    eng.set_item(items[0].id, CHK_TODO, auto=True)
    result = evaluate(eng, items, [])
    assert result.status == VERDICT_INCOMPLETE


def test_incomplete_when_not_signed():
    items = load_checklist()
    eng = _all_pass_engagement(items, signed=False)
    result = evaluate(eng, items, [])
    assert result.status == VERDICT_INCOMPLETE
    assert any("sign-off" in r.lower() for r in result.reasons)


def test_incomplete_on_open_medium_not_accepted():
    items = load_checklist()
    eng = _all_pass_engagement(items)
    result = evaluate(eng, items, [_f(SEVERITY_MEDIUM)])
    assert result.status == VERDICT_INCOMPLETE


def test_pass_when_medium_accepted_and_signed():
    items = load_checklist()
    eng = _all_pass_engagement(items)
    result = evaluate(eng, items, [_f(SEVERITY_MEDIUM, status=STATUS_ACCEPTED)])
    assert result.status == VERDICT_PASS


def test_pass_when_high_fixed():
    items = load_checklist()
    eng = _all_pass_engagement(items)
    result = evaluate(eng, items, [_f(SEVERITY_HIGH, status=STATUS_FIXED)])
    assert result.status == VERDICT_PASS


def test_manual_items_do_not_block_tool_verdict():
    """Item murni manual (type=manual) TIDAK boleh membuat verdict tool INCOMPLETE."""
    items = load_checklist()
    eng = Engagement(name="e")
    eng.ensure_items(items)
    # Hanya item tool (auto+hybrid) yang di-pass; item manual sengaja dibiarkan TODO.
    for it in items:
        if it.is_auto:
            eng.set_item(it.id, CHK_PASS, note="ok", auto=True)
    eng.signoff = {"name": "T", "statement": "s", "signed_at": "now"}
    result = evaluate(eng, items, [])
    assert result.status == VERDICT_PASS
    # Tidak ada item manual yang disebut sebagai alasan.
    manual_ids = [it.id for it in items if not it.is_auto]
    assert not any(mid in r for r in result.reasons for mid in manual_ids)


def test_manual_pass_requires_evidence():
    items = load_checklist()
    eng = Engagement(name="e")
    eng.ensure_items(items)
    for it in items:
        # tandai semua pass secara MANUAL (auto=False) tanpa bukti
        eng.set_item(it.id, CHK_PASS, note="ok", auto=False)
    eng.signoff = {"name": "T", "statement": "s", "signed_at": "now"}
    result = evaluate(eng, items, [])
    # item manual pass tanpa bukti -> INCOMPLETE
    assert result.status == VERDICT_INCOMPLETE
    assert any("tanpa bukti" in r for r in result.reasons)
