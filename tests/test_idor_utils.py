from src.core.idor_utils import is_uuid, response_similarity


def test_is_uuid_valid():
    assert is_uuid("550e8400-e29b-41d4-a716-446655440000") is True


def test_is_uuid_uppercase_valid():
    assert is_uuid("550E8400-E29B-41D4-A716-446655440000") is True


def test_is_uuid_numeric_false():
    assert is_uuid("42") is False


def test_is_uuid_empty_false():
    assert is_uuid("") is False


def test_response_similarity_identical():
    assert response_similarity("hello world", "hello world") == 1.0


def test_response_similarity_different():
    assert response_similarity("aaaa", "zzzz") < 0.5


def test_response_similarity_none_safe():
    assert response_similarity(None, "x") == 0.0
