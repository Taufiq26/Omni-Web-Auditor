import pytest
from src.core.scope import Scope, ScopeError


def test_exact_host_in_scope():
    s = Scope.from_list(["example.com"])
    assert s.is_in_scope("https://example.com/path") is True


def test_subdomain_allowed_by_default():
    s = Scope.from_list(["example.com"])
    assert s.is_in_scope("https://storage.example.com") is True


def test_subdomain_blocked_when_disabled():
    s = Scope.from_list(["example.com"], allow_subdomains=False)
    assert s.is_in_scope("https://storage.example.com") is False


def test_out_of_scope_host():
    s = Scope.from_list(["example.com"])
    assert s.is_in_scope("https://evil.com") is False


def test_sibling_domain_not_matched_as_subdomain():
    # "notexample.com" tidak boleh cocok dengan "example.com"
    s = Scope.from_list(["example.com"])
    assert s.is_in_scope("https://notexample.com") is False


def test_ip_in_scope():
    s = Scope.from_list(["203.0.113.10"])
    assert s.is_in_scope("http://203.0.113.10:8080/x") is True


def test_require_raises_out_of_scope():
    s = Scope.from_list(["example.com"])
    with pytest.raises(ScopeError):
        s.require("https://evil.com")


def test_require_passes_in_scope():
    s = Scope.from_list(["example.com"])
    s.require("https://example.com")  # tidak melempar


def test_bare_host_input():
    s = Scope.from_list(["example.com"])
    assert s.is_in_scope("example.com:443/path") is True
