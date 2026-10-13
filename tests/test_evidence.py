import os
from src.core.evidence import sha256_file, redact_sensitive, store_evidence, store_text_evidence


def test_redact_sensitive_headers():
    raw = "GET / HTTP/1.1\nHost: x\nAuthorization: Bearer secrettoken\nCookie: s=abc\n"
    out = redact_sensitive(raw)
    assert "secrettoken" not in out
    assert "s=abc" not in out
    assert "[REDACTED]" in out
    assert "Host: x" in out  # header non-sensitif tetap


def test_store_evidence_hashes(tmp_path):
    src = tmp_path / "shot.png"
    src.write_bytes(b"\x89PNG fake")
    ev_dir = tmp_path / "ev"
    ref = store_evidence(str(ev_dir), str(src), desc="bukti")
    stored = os.path.join(os.path.dirname(str(ev_dir)), ref["path"])
    assert os.path.exists(stored)
    assert ref["sha256"] == sha256_file(stored)
    assert ref["desc"] == "bukti"


def test_store_text_evidence_redacts(tmp_path):
    ev_dir = tmp_path / "ev"
    ref = store_text_evidence(str(ev_dir), "req.txt", "Authorization: Bearer xyz\nbody", desc="req")
    stored = os.path.join(os.path.dirname(str(ev_dir)), ref["path"])
    content = open(stored).read()
    assert "xyz" not in content and "[REDACTED]" in content


def test_store_evidence_missing_file(tmp_path):
    import pytest
    with pytest.raises(FileNotFoundError):
        store_evidence(str(tmp_path / "ev"), str(tmp_path / "nope.png"))
