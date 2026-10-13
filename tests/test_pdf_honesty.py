"""Memastikan laporan tidak mengklaim 'SECURE' saat ada tes yang dilewati."""
from src.reports.pdf_gen import PDFReportGenerator
from src.core.coverage import coverage_entry, STATUS_TESTED, STATUS_SKIPPED
from src.core.models import Finding


def test_secure_when_no_findings_and_all_tested():
    cov = [coverage_entry("Security headers", STATUS_TESTED, "ok")]
    gen = PDFReportGenerator([], "https://x", coverage=cov)
    status, _, _ = gen._get_health_status()
    assert status == "SECURE"


def test_inconclusive_when_tests_skipped():
    cov = [coverage_entry("IDOR", STATUS_SKIPPED, "no creds")]
    gen = PDFReportGenerator([], "https://x", coverage=cov)
    status, _, _ = gen._get_health_status()
    assert status == "INCONCLUSIVE"


def test_findings_override_coverage():
    cov = [coverage_entry("IDOR", STATUS_SKIPPED, "no creds")]
    findings = [Finding(vulnerability="X", severity="High", location="x", evidence="e", remediation="r")]
    gen = PDFReportGenerator(findings, "https://x", coverage=cov)
    status, _, _ = gen._get_health_status()
    assert status == "CRITICAL"
