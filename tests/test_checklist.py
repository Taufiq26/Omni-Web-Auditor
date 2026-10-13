import pytest
from src.checklist.loader import load_checklist, ChecklistItem
from src.checklist import loader


def test_load_checklist_nonempty():
    items = load_checklist()
    assert len(items) > 20
    assert all(isinstance(it, ChecklistItem) for it in items)


def test_all_ids_unique_and_wstg():
    items = load_checklist()
    ids = [it.id for it in items]
    assert len(ids) == len(set(ids))
    assert all(i.startswith("WSTG-") for i in ids)


def test_auto_items_have_sources():
    items = load_checklist()
    for it in items:
        if it.type in ("auto", "hybrid"):
            assert it.sources, f"{it.id} auto/hybrid tapi tanpa sources"


def test_is_auto_property():
    items = {it.id: it for it in load_checklist()}
    assert items["WSTG-CONF-07"].is_auto is True
    assert items["WSTG-BUSL-01"].is_auto is False


def test_reject_bad_type(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("items:\n  - id: X\n    category: C\n    title: T\n    type: weird\n")
    with pytest.raises(ValueError):
        loader.load_checklist(str(bad))
