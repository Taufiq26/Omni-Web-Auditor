"""ScannerSession menegakkan scope sebelum request keluar (tanpa jaringan)."""
import pytest
from src.core.session import ScannerSession
from src.core.scope import Scope, ScopeError


def test_session_blocks_out_of_scope_get():
    session = ScannerSession(scope=Scope.from_list(["example.com"]))
    # Harus melempar ScopeError SEBELUM request jaringan apa pun.
    with pytest.raises(ScopeError):
        session.get_request("https://evil.com/steal")


def test_session_blocks_out_of_scope_request_method():
    session = ScannerSession(scope=Scope.from_list(["example.com"]))
    with pytest.raises(ScopeError):
        session.request("POST", "https://evil.com/api")


def test_session_without_scope_does_not_enforce():
    # Tanpa scope, _enforce_scope tidak melempar (backward compatible).
    session = ScannerSession()
    session._enforce_scope("https://anything.com")  # tidak melempar
