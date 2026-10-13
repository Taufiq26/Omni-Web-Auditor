from src.reports.rationale import secure_reason, count_related_findings


def test_secure_reason_known_test():
    reason = secure_reason("SSL/TLS")
    assert "TLS" in reason or "sertifikat" in reason.lower()


def test_secure_reason_unknown_fallback():
    assert secure_reason("Sesuatu Yang Baru") != ""


def test_count_related_findings_matches_ssl():
    findings = [{"vulnerability": "Obsolete SSL/TLS Protocol"}]
    assert count_related_findings("SSL/TLS", findings) == 1


def test_count_related_findings_zero_when_unrelated():
    findings = [{"vulnerability": "Exposed .env File"}]
    assert count_related_findings("SSL/TLS", findings) == 0


def test_count_related_findings_idor():
    findings = [{"vulnerability": "Broken Object Level Authorization (BOLA/IDOR)"}]
    assert count_related_findings("IDOR/BOLA (ID+1 sekuensial)", findings) == 1
