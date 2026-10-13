from benchmark.matching import finding_matches, any_finding_matches, is_applicable
from src.core.models import Finding


def _f(vuln, wstg=()):
    return Finding(vulnerability=vuln, severity="High", location="x",
                   evidence="e", remediation="r", wstg_ids=wstg)


def test_match_by_keyword():
    f = _f("Missing Security Header: CSP")
    assert finding_matches(f, ["missing security header"]) is True


def test_match_by_wstg_id():
    f = _f("Anything", wstg=("WSTG-INPV-05",))
    assert finding_matches(f, ["WSTG-INPV-05"]) is True


def test_no_match():
    f = _f("Outdated Library")
    assert finding_matches(f, ["sql injection", "WSTG-INPV-05"]) is False


def test_any_finding_matches():
    findings = [_f("X"), _f("SQL Injection pada id")]
    assert any_finding_matches(findings, ["sql injection"]) is True


def test_is_applicable_intersection():
    assert is_applicable(["zap", "native"], ["native"]) is True
    assert is_applicable(["zap", "sqlmap"], ["native"]) is False
