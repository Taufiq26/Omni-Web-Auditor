"""Loader & validator untuk file endpoint pengujian (--endpoints-file).

File ini WAJIB disiapkan manual oleh penguji dari dokumentasi API resmi target
(mis. api-contract.md), BUKAN hasil crawling otomatis. Inilah batas yang menjaga
tool tetap etis: tool hanya menyentuh endpoint yang sudah ada dalam scope izin
(docs/07-perbaikan-cakupan-scan.md, Masalah #1 poin 3 & Masalah #2).

Skema JSON yang diterima:

{
  "injection_tests": [
    {"method": "POST", "url": "https://api.example.com/login",
     "body": {"email": "{{INJECT}}", "password": "x"}},
    {"method": "GET", "url": "https://api.example.com/search",
     "query": {"q": "{{INJECT}}"}}
  ],
  "idor_object_urls": [
    "https://api.example.com/api/passes/<UUID-objek-milik-akun-A>"
  ]
}

- injection_tests: untuk uji SQLi/XSS berbasis body/query JSON. Field apa pun
  yang bernilai tepat "{{INJECT}}" akan jadi titik injeksi.
- idor_object_urls: URL objek yang dimiliki akun uji A (disiapkan penguji). Tool
  akan mengaksesnya dengan token A lalu token B untuk uji IDOR dua-akun.
"""

import json
from dataclasses import dataclass, field
from typing import List, Dict, Any

INJECT_MARKER = "{{INJECT}}"
_VALID_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}


@dataclass(frozen=True)
class EndpointsConfig:
    """Konfigurasi endpoint hasil parse (immutable)."""
    injection_tests: List[Dict[str, Any]] = field(default_factory=list)
    idor_object_urls: List[str] = field(default_factory=list)


def _validate_injection_test(item: Any, index: int) -> Dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError(f"injection_tests[{index}] harus berupa objek JSON.")

    method = str(item.get("method", "GET")).upper()
    if method not in _VALID_METHODS:
        raise ValueError(
            f"injection_tests[{index}].method '{method}' tidak valid "
            f"(harus salah satu dari {sorted(_VALID_METHODS)})."
        )

    url = item.get("url")
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        raise ValueError(
            f"injection_tests[{index}].url wajib ada dan diawali http:// atau https://."
        )

    body = item.get("body", {})
    query = item.get("query", {})
    if not isinstance(body, dict) or not isinstance(query, dict):
        raise ValueError(f"injection_tests[{index}].body/query harus berupa objek JSON.")

    # Pastikan ada minimal satu titik injeksi, biar tidak sekadar request kosong.
    has_marker = any(v == INJECT_MARKER for v in body.values()) or any(
        v == INJECT_MARKER for v in query.values()
    )
    if not has_marker:
        raise ValueError(
            f"injection_tests[{index}] tidak punya penanda '{INJECT_MARKER}' "
            "di body maupun query."
        )

    return {"method": method, "url": url, "body": dict(body), "query": dict(query)}


def parse_endpoints(data: Any) -> EndpointsConfig:
    """Validasi struktur dict JSON menjadi EndpointsConfig. Fail-fast bila salah."""
    if not isinstance(data, dict):
        raise ValueError("Isi endpoints-file harus berupa objek JSON di level teratas.")

    raw_injection = data.get("injection_tests", [])
    if not isinstance(raw_injection, list):
        raise ValueError("Field 'injection_tests' harus berupa array.")
    injection_tests = [
        _validate_injection_test(item, i) for i, item in enumerate(raw_injection)
    ]

    raw_idor = data.get("idor_object_urls", [])
    if not isinstance(raw_idor, list):
        raise ValueError("Field 'idor_object_urls' harus berupa array.")
    idor_object_urls = []
    for i, url in enumerate(raw_idor):
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            raise ValueError(
                f"idor_object_urls[{i}] harus string URL diawali http:// atau https://."
            )
        idor_object_urls.append(url)

    return EndpointsConfig(
        injection_tests=injection_tests,
        idor_object_urls=idor_object_urls,
    )


def load_endpoints_file(path: str) -> EndpointsConfig:
    """Baca & validasi file endpoints dari disk."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise ValueError(f"File endpoints tidak ditemukan: {path}")
    except json.JSONDecodeError as e:
        raise ValueError(f"File endpoints bukan JSON valid ({path}): {e}")
    return parse_endpoints(data)
