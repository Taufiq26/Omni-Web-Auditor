import pytest
from src.core import engagement as eng_mod
from src.core.engagement import Engagement, CHK_PASS
from src.core.models import Finding


@pytest.fixture(autouse=True)
def _tmp_engagements(tmp_path, monkeypatch):
    monkeypatch.setattr(eng_mod, "ENGAGEMENTS_DIR", str(tmp_path / "engagements"))


def test_create_save_load_roundtrip():
    eng = Engagement(name="e1", target="https://x.com", scope=["x.com"])
    eng.ensure_items()
    eng.set_item("WSTG-CONF-07", CHK_PASS, note="ok")
    eng.save()

    loaded = Engagement.load("e1")
    assert loaded.target == "https://x.com"
    assert loaded.item_states["WSTG-CONF-07"]["status"] == CHK_PASS


def test_exists():
    assert Engagement.exists("nope") is False
    Engagement(name="e2").save()
    assert Engagement.exists("e2") is True


def test_replace_findings_serializes():
    eng = Engagement(name="e3")
    f = Finding(vulnerability="X", severity="High", location="l", evidence="e", remediation="r",
                wstg_ids=("WSTG-INPV-05",))
    eng.replace_findings([f])
    eng.save()
    loaded = Engagement.load("e3")
    assert loaded.findings[0]["vulnerability"] == "X"
    assert loaded.findings[0]["wstg_ids"] == ["WSTG-INPV-05"]


def test_set_item_rejects_bad_status():
    eng = Engagement(name="e4")
    with pytest.raises(ValueError):
        eng.set_item("WSTG-CONF-07", "bogus")
