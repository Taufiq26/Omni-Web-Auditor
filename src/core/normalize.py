"""Normalisasi & dedup temuan dari berbagai sumber.

Temuan dari native checks + adapter eksternal bisa tumpang tindih (mis. header
hilang terdeteksi native & ZAP). Dedup berdasarkan (kategori, lokasi) sambil
mempertahankan severity tertinggi dan mencatat sumber-sumber yang sepakat.
"""

import re
from typing import List
from dataclasses import replace

from src.core.models import Finding, severity_rank

_NORMALIZE_RE = re.compile(r"[^a-z0-9]+")


def _category_key(vulnerability: str) -> str:
    """Kunci kategori kasar dari judul (lowercase, tanpa detail/angka)."""
    low = vulnerability.lower()
    # buang detail dalam kurung dan nama parameter setelah "pada '...'"
    low = re.sub(r"\(.*?\)", "", low)
    low = re.sub(r"pada '.*?'", "", low)
    return _NORMALIZE_RE.sub("-", low).strip("-")


def _dedup_key(finding: Finding) -> tuple:
    return (_category_key(finding.vulnerability), finding.location)


def deduplicate(findings: List[Finding]) -> List[Finding]:
    """Gabungkan temuan duplikat (kategori+lokasi sama).

    Yang dipertahankan: severity tertinggi. Sumber yang sepakat dicatat di evidence.
    Union wstg_ids & cvss_vector pertama yang ada tetap dibawa.
    """
    best: dict = {}
    sources: dict = {}
    wstg: dict = {}

    for f in findings:
        key = _dedup_key(f)
        sources.setdefault(key, set()).add(f.source)
        wstg.setdefault(key, set()).update(f.wstg_ids)
        current = best.get(key)
        if current is None or severity_rank(f.severity) > severity_rank(current.severity):
            best[key] = f

    result = []
    for key, f in best.items():
        srcs = sorted(sources[key])
        merged = replace(f, wstg_ids=tuple(sorted(wstg[key])))
        if len(srcs) > 1:
            merged = replace(merged, evidence=f"{merged.evidence}\n[dikonfirmasi oleh: {', '.join(srcs)}]")
        result.append(merged)

    # Urutkan dari severity tertinggi untuk laporan.
    result.sort(key=lambda x: severity_rank(x.severity), reverse=True)
    return result
