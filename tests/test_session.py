"""Tes ScannerSession dengan requests.Session di-fake (tanpa jaringan)."""
from requests.exceptions import RequestException
from src.core.session import ScannerSession


class _FakeInner:
    def __init__(self, raise_exc=False):
        self.raise_exc = raise_exc
        self.headers = {}
        self.calls = []

    def get(self, url, **kwargs):
        return self._maybe(("GET", url))

    def post(self, url, **kwargs):
        return self._maybe(("POST", url))

    def request(self, method, url, **kwargs):
        return self._maybe((method, url))

    def _maybe(self, rec):
        self.calls.append(rec)
        if self.raise_exc:
            raise RequestException("boom")
        return f"resp:{rec}"


def _session(raise_exc=False):
    s = ScannerSession()
    s.session = _FakeInner(raise_exc=raise_exc)
    return s


def test_headers_set_with_creds():
    s = ScannerSession(cookie="a=b", bearer_token="tok")
    assert s.session.headers["Cookie"] == "a=b"
    assert s.session.headers["Authorization"] == "Bearer tok"


def test_get_request_ok():
    s = _session()
    assert s.get_request("https://x.com").startswith("resp:")


def test_get_request_handles_exception():
    s = _session(raise_exc=True)
    assert s.get_request("https://x.com") is None


def test_post_and_request_methods():
    s = _session()
    assert s.post_request("https://x.com", json={"a": 1}).startswith("resp:")
    assert s.request("PUT", "https://x.com").startswith("resp:")


def test_request_handles_exception():
    s = _session(raise_exc=True)
    assert s.request("DELETE", "https://x.com") is None
