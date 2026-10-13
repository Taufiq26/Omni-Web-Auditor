"""Tes InfraScanner dengan socket/sesi palsu (tanpa jaringan)."""
import socket
from src.modules import infra_scan
from src.modules.infra_scan import InfraScanner
from src.core.coverage import STATUS_TESTED, STATUS_SKIPPED


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class FakeSession:
    def __init__(self, resp=None):
        self.resp = resp

    def get_request(self, url, **kwargs):
        return self.resp


class _FakeSock:
    """Socket palsu: connect_ex mengembalikan nilai dari peta port."""
    def __init__(self, open_ports):
        self.open_ports = open_ports
        self._port = None

    def settimeout(self, t): pass
    def connect_ex(self, addr):
        self._port = addr[1]
        return 0 if addr[1] in self.open_ports else 1
    def recv(self, n):
        return b"SSH-2.0-OpenSSH_6.6p1 Ubuntu"
    def close(self): pass


def test_scan_open_ports_detects_open(monkeypatch):
    monkeypatch.setattr(infra_scan.socket, "socket", lambda *a, **k: _FakeSock({3306}))
    findings = InfraScanner().scan_open_ports("1.2.3.4")
    assert any("MySQL" in f.vulnerability and f.severity == "High" for f in findings)


def test_scan_open_ports_none_open(monkeypatch):
    monkeypatch.setattr(infra_scan.socket, "socket", lambda *a, **k: _FakeSock(set()))
    assert InfraScanner().scan_open_ports("1.2.3.4") == []


def test_audit_ssh_outdated(monkeypatch):
    monkeypatch.setattr(infra_scan.socket, "socket", lambda *a, **k: _FakeSock({22}))
    findings = InfraScanner().audit_ssh_service("1.2.3.4")
    assert any("Outdated SSH" in f.vulnerability for f in findings)


def test_select_scan_ip_cdn_skips(monkeypatch):
    # IP resolve ke range Cloudflare -> scan dilewati, coverage SKIPPED.
    monkeypatch.setattr(infra_scan.socket, "gethostbyname", lambda h: "104.16.0.1")
    scanner = InfraScanner(session=FakeSession(FakeResponse(headers={})))
    ip = scanner._select_scan_ip("https://x.com", "x.com")
    assert ip is None
    assert any(c.status == STATUS_SKIPPED and c.test == "Port/SSH scan" for c in scanner.coverage)


def test_select_scan_ip_origin_ip_wins():
    scanner = InfraScanner(origin_ip="203.0.113.9")
    ip = scanner._select_scan_ip("https://x.com", "x.com")
    assert ip == "203.0.113.9"
    assert any(c.status == STATUS_TESTED for c in scanner.coverage)


def test_select_scan_ip_non_cdn(monkeypatch):
    monkeypatch.setattr(infra_scan.socket, "gethostbyname", lambda h: "8.8.8.8")
    scanner = InfraScanner(session=FakeSession(FakeResponse(headers={"Server": "nginx"})))
    ip = scanner._select_scan_ip("https://x.com", "x.com")
    assert ip == "8.8.8.8"


def test_resolve_fails(monkeypatch):
    def _raise(h): raise socket.gaierror()
    monkeypatch.setattr(infra_scan.socket, "gethostbyname", _raise)
    scanner = InfraScanner(session=FakeSession(None))
    assert scanner._select_scan_ip("https://x.com", "x.com") is None
