import pytest
from dataclasses import FrozenInstanceError
from src.core.models import (
    Finding, severity_rank,
    SEVERITY_HIGH, SEVERITY_LOW, SEVERITY_CRITICAL,
    STATUS_OPEN, STATUS_ACCEPTED,
)


def _f(**kw):
    base = dict(vulnerability="X", severity=SEVERITY_HIGH, location="l", evidence="e", remediation="r")
    base.update(kw)
    return Finding(**base)


def test_finding_is_immutable():
    f = _f()
    with pytest.raises(FrozenInstanceError):
        f.severity = SEVERITY_LOW


def test_finding_defaults():
    f = _f()
    assert f.source == "native"
    assert f.status == STATUS_OPEN
    assert f.wstg_ids == ()


def test_with_status_returns_new_object():
    f = _f()
    updated = f.with_status(STATUS_ACCEPTED, note="risk accepted")
    assert updated is not f
    assert updated.status == STATUS_ACCEPTED
    assert f.status == STATUS_OPEN  # asli tidak berubah
    assert "risk accepted" in updated.evidence


def test_severity_rank_ordering():
    assert severity_rank(SEVERITY_CRITICAL) > severity_rank(SEVERITY_HIGH) > severity_rank(SEVERITY_LOW)


def test_severity_rank_unknown():
    assert severity_rank("Nonsense") == 0
