"""Tes behavior ActiveScanner dengan sesi palsu (tanpa jaringan).

time.sleep di-patch ke no-op supaya tes cepat.
"""
import pytest
from src.modules.active_scan import ActiveScanner
from src.core.endpoints import EndpointsConfig
from src.core.coverage import STATUS_TESTED, STATUS_SKIPPED, STATUS_NOT_APPLICABLE


class FakeResponse:
    def __init__(self, status_code=200, text="", content_type="application/json"):
        self.status_code = status_code
        self.text = text
        self.headers = {"Content-Type": content_type}


class FakeSession:
    """Membalas berdasarkan peta url->FakeResponse (atau default)."""
    def __init__(self, mapping=None, default=None):
        self.mapping = mapping or {}
        self.default = default
        self.calls = []

    def get_request(self, url, **kwargs):
        self.calls.append(url)
        for key, resp in self.mapping.items():
            if key in url:
                return resp
        return self.default

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.default


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr("src.modules.active_scan.time.sleep", lambda *_: None)


def _coverage_status(scanner, test_name):
    return next((c.status for c in scanner.coverage if c.test == test_name), None)


def test_idor_uuid_marked_not_applicable():
    s = FakeSession()
    scanner = ActiveScanner(s)
    url = "https://api.x/api/passes/550e8400-e29b-41d4-a716-446655440000"
    findings = scanner.check_api_idor(url)
    assert findings == []
    assert _coverage_status(scanner, "IDOR/BOLA (ID+1 sekuensial)") == STATUS_NOT_APPLICABLE


def test_idor_numeric_false_positive_suppressed():
    # Endpoint balas 200 identik untuk id valid DAN id kontrol -> bukan IDOR.
    same = FakeResponse(200, text='{"generic":"page"}')
    s = FakeSession(default=same)
    scanner = ActiveScanner(s)
    findings = scanner.check_api_idor("https://api.x/api/orders/42")
    assert findings == []


def test_idor_numeric_real_finding():
    # id+1 balas data berbeda dari id kontrol -> IDOR valid.
    def session_factory():
        class S:
            def get_request(self, url, **kwargs):
                if "987654" in url:  # control id tak-ada
                    return FakeResponse(404, text="not found", content_type="text/html")
                return FakeResponse(200, text='{"owner":"other","secret":1}')
        return S()
    scanner = ActiveScanner(session_factory())
    findings = scanner.check_api_idor("https://api.x/api/orders/42")
    assert len(findings) == 1
    assert "BOLA" in findings[0].vulnerability


def test_two_account_idor_detected():
    owner_obj = FakeResponse(200, text='{"id":"abc","owner":"A","data":"secret"}')
    session_a = FakeSession(default=owner_obj)
    session_b = FakeSession(default=owner_obj)  # B melihat objek A -> IDOR
    cfg = EndpointsConfig(idor_object_urls=["https://api.x/api/passes/abc"])
    scanner = ActiveScanner(session_a, endpoints=cfg, session_b=session_b)
    findings = scanner.check_idor_two_account()
    assert len(findings) == 1
    assert "Cross-Account" in findings[0].vulnerability
    assert _coverage_status(scanner, "IDOR/BOLA (dua-akun UUID)") == STATUS_TESTED


def test_two_account_idor_protected():
    owner_obj = FakeResponse(200, text='{"id":"abc","owner":"A"}')
    denied = FakeResponse(403, text="forbidden", content_type="text/html")
    session_a = FakeSession(default=owner_obj)
    session_b = FakeSession(default=denied)  # B ditolak -> aman
    cfg = EndpointsConfig(idor_object_urls=["https://api.x/api/passes/abc"])
    scanner = ActiveScanner(session_a, endpoints=cfg, session_b=session_b)
    findings = scanner.check_idor_two_account()
    assert findings == []
    assert _coverage_status(scanner, "IDOR/BOLA (dua-akun UUID)") == STATUS_TESTED


def test_two_account_skipped_without_session_b():
    cfg = EndpointsConfig(idor_object_urls=["https://api.x/api/passes/abc"])
    scanner = ActiveScanner(FakeSession(), endpoints=cfg, session_b=None)
    findings = scanner.check_idor_two_account()
    assert findings == []
    assert _coverage_status(scanner, "IDOR/BOLA (dua-akun UUID)") == STATUS_SKIPPED


def test_body_injection_detects_sql_error():
    sql_err = FakeResponse(200, text="You have an error in your SQL syntax near", content_type="application/json")
    s = FakeSession(default=sql_err)
    cfg = EndpointsConfig(injection_tests=[
        {"method": "POST", "url": "https://api.x/login", "body": {"email": "{{INJECT}}"}, "query": {}}
    ])
    scanner = ActiveScanner(s, endpoints=cfg)
    findings = scanner.test_input_validation_body()
    assert any("SQL Injection" in f.vulnerability for f in findings)
