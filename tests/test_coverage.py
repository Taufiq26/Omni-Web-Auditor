import pytest
from src.core.coverage import coverage_entry, STATUS_TESTED, STATUS_SKIPPED


def test_coverage_entry_shape():
    e = coverage_entry("Port scan", STATUS_TESTED, "done")
    assert (e.test, e.status, e.detail) == ("Port scan", "TESTED", "done")


def test_coverage_entry_rejects_bad_status():
    with pytest.raises(ValueError):
        coverage_entry("x", "WEIRD", "y")


def test_coverage_skipped_status():
    e = coverage_entry("IDOR", STATUS_SKIPPED, "no creds")
    assert e.status == "SKIPPED"
