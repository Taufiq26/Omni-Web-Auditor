"""Tes BasicScanner dengan sesi palsu (tanpa jaringan)."""
import socket
from src.modules import basic_scan
from src.modules.basic_scan import BasicScanner


class FakeResponse:
    def __init__(self, status_code=200, headers=None, text="", content=b""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.content = content


class FakeSession:
    def __init__(self, mapping=None, default=None):
        self.mapping = mapping or {}
        self.default = default

    def get_request(self, url, **kwargs):
        for key, resp in self.mapping.items():
            if key in url:
                return resp
        return self.default


def test_missing_security_headers_all():
    session = FakeSession(default=FakeResponse(headers={}))
    findings = BasicScanner(session).check_security_headers("https://x.com")
    assert len(findings) == 4
    assert all("Missing Security Header" in f.vulnerability for f in findings)


def test_present_headers_no_findings():
    headers = {
        "Strict-Transport-Security": "x", "Content-Security-Policy": "x",
        "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
    }
    session = FakeSession(default=FakeResponse(headers=headers))
    assert BasicScanner(session).check_security_headers("https://x.com") == []


def test_check_security_headers_none_response():
    session = FakeSession(default=None)
    assert BasicScanner(session).check_security_headers("https://x.com") == []


def test_exposed_env_file_detected():
    resp = FakeResponse(status_code=200, text="DB_PASSWORD=secret\nAPP_KEY=abc")
    session = FakeSession(mapping={"/.env": resp}, default=FakeResponse(status_code=404))
    findings = BasicScanner(session).check_exposed_files("https://x.com")
    assert any("Exposed .env File" in f.vulnerability for f in findings)


def test_exposed_binary_ds_store():
    resp = FakeResponse(status_code=200, content=b"Bud1\x00\x00")
    session = FakeSession(mapping={"/.DS_Store": resp}, default=FakeResponse(status_code=404))
    findings = BasicScanner(session).check_exposed_files("https://x.com")
    assert any(".DS_Store" in f.vulnerability for f in findings)


def test_run_scan_records_coverage(monkeypatch):
    # Hindari koneksi SSL nyata: paksa timeout.
    def _raise(*a, **k):
        raise socket.timeout()
    monkeypatch.setattr(basic_scan.socket, "create_connection", _raise)
    session = FakeSession(default=FakeResponse(headers={}, status_code=404))
    scanner = BasicScanner(session)
    scanner.run_scan("https://x.com")
    tests = {c.test for c in scanner.coverage}
    assert {"Security headers", "SSL/TLS", "Exposed sensitive files"} <= tests
