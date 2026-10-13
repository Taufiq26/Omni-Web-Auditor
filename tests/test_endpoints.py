import pytest
from src.core.endpoints import parse_endpoints, INJECT_MARKER


def test_parse_valid_injection_body():
    cfg = parse_endpoints({
        "injection_tests": [
            {"method": "POST", "url": "https://api.x/login", "body": {"email": INJECT_MARKER, "p": "x"}}
        ]
    })
    assert len(cfg.injection_tests) == 1
    assert cfg.injection_tests[0]["method"] == "POST"


def test_parse_valid_idor_urls():
    cfg = parse_endpoints({"idor_object_urls": ["https://api.x/passes/abc"]})
    assert cfg.idor_object_urls == ["https://api.x/passes/abc"]


def test_empty_config_ok():
    cfg = parse_endpoints({})
    assert cfg.injection_tests == []
    assert cfg.idor_object_urls == []


def test_reject_non_dict_top_level():
    with pytest.raises(ValueError):
        parse_endpoints([])


def test_reject_injection_without_marker():
    with pytest.raises(ValueError):
        parse_endpoints({
            "injection_tests": [{"method": "POST", "url": "https://api.x", "body": {"a": "b"}}]
        })


def test_reject_bad_method():
    with pytest.raises(ValueError):
        parse_endpoints({
            "injection_tests": [{"method": "FETCH", "url": "https://api.x", "body": {"a": INJECT_MARKER}}]
        })


def test_reject_url_without_scheme():
    with pytest.raises(ValueError):
        parse_endpoints({"idor_object_urls": ["api.x/passes/abc"]})
