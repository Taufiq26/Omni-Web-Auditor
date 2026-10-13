from src.core.normalize import deduplicate, _category_key
from src.core.models import Finding, SEVERITY_HIGH, SEVERITY_LOW, SEVERITY_MEDIUM


def _f(vuln, sev, loc="http://x", source="native", wstg=()):
    return Finding(vulnerability=vuln, severity=sev, location=loc,
                   evidence="e", remediation="r", source=source, wstg_ids=wstg)


def test_category_key_strips_details():
    assert _category_key("Potential SQL Injection pada 'id'") == _category_key("Potential SQL Injection pada 'name'")


def test_dedup_merges_same_category_location():
    findings = [
        _f("Missing Security Header: CSP", SEVERITY_LOW, source="native"),
        _f("Missing Security Header: CSP", SEVERITY_MEDIUM, source="zap"),
    ]
    result = deduplicate(findings)
    assert len(result) == 1
    assert result[0].severity == SEVERITY_MEDIUM  # severity tertinggi dipertahankan
    assert "dikonfirmasi oleh" in result[0].evidence


def test_dedup_keeps_distinct_locations():
    findings = [
        _f("X", SEVERITY_LOW, loc="http://a"),
        _f("X", SEVERITY_LOW, loc="http://b"),
    ]
    assert len(deduplicate(findings)) == 2


def test_dedup_sorts_by_severity_desc():
    findings = [_f("A", SEVERITY_LOW, loc="l1"), _f("B", SEVERITY_HIGH, loc="l2")]
    result = deduplicate(findings)
    assert result[0].severity == SEVERITY_HIGH


def test_dedup_union_wstg():
    findings = [
        _f("SQLi", SEVERITY_HIGH, source="native", wstg=("WSTG-INPV-05",)),
        _f("SQLi", SEVERITY_HIGH, source="zap", wstg=("WSTG-INPV-05", "WSTG-INPV-06")),
    ]
    result = deduplicate(findings)
    assert set(result[0].wstg_ids) == {"WSTG-INPV-05", "WSTG-INPV-06"}
