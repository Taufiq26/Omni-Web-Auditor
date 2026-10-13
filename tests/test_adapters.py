"""Tes parser adapter dengan contoh output asli (tanpa Docker/jaringan)."""

from src.adapters.nuclei import parse_nuclei_jsonl
from src.adapters.testssl import parse_testssl_json
from src.adapters.zap import parse_zap_json
from src.adapters.sqlmap import parse_sqlmap_output
from src.core.models import SEVERITY_HIGH, SOURCE_NUCLEI, SOURCE_ZAP


# --- nuclei ---
def test_parse_nuclei_jsonl():
    line = (
        '{"template-id":"CVE-2021-1234","matched-at":"http://x/","info":'
        '{"name":"Example RCE","severity":"critical","description":"desc",'
        '"classification":{"cve-id":["CVE-2021-1234"]}}}'
    )
    findings = parse_nuclei_jsonl(line + "\n")
    assert len(findings) == 1
    assert findings[0].severity == "Critical"
    assert findings[0].source == SOURCE_NUCLEI
    assert "CVE-2021-1234" in findings[0].vulnerability


def test_parse_nuclei_skips_bad_lines():
    assert parse_nuclei_jsonl("not json\n\n") == []


# --- testssl ---
def test_parse_testssl_flat_list():
    data = (
        '[{"id":"SSLv3","severity":"HIGH","finding":"SSLv3 offered","ip":"1.2.3.4"},'
        '{"id":"cipher_x","severity":"OK","finding":"fine","ip":"1.2.3.4"}]'
    )
    findings = parse_testssl_json(data)
    assert len(findings) == 1  # OK diabaikan
    assert findings[0].severity == SEVERITY_HIGH
    assert "SSLv3" in findings[0].vulnerability


def test_parse_testssl_bad_json():
    assert parse_testssl_json("oops") == []


# --- ZAP ---
def test_parse_zap_json():
    data = (
        '{"site":[{"@name":"http://x","alerts":[{"name":"SQL Injection",'
        '"riskcode":"3","desc":"<p>bad</p>","solution":"<p>fix</p>",'
        '"instances":[{"uri":"http://x/q"}]}]}]}'
    )
    findings = parse_zap_json(data)
    assert len(findings) == 1
    assert findings[0].severity == SEVERITY_HIGH
    assert findings[0].source == SOURCE_ZAP
    assert findings[0].location == "http://x/q"
    assert "bad" in findings[0].evidence and "<p>" not in findings[0].evidence
    assert "WSTG-INPV-05" in findings[0].wstg_ids


# --- sqlmap ---
def test_parse_sqlmap_confirmed():
    out = "sqlmap identified the following injection point(s)\nParameter: id (GET)\n  Type: boolean-based blind"
    findings = parse_sqlmap_output(out, "http://x/item?id=1")
    assert len(findings) == 1
    assert "id" in findings[0].vulnerability


def test_parse_sqlmap_not_vulnerable():
    assert parse_sqlmap_output("all tested parameters do not appear to be injectable", "http://x") == []
