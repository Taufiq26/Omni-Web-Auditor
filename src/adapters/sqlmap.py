"""Adapter sqlmap — konfirmasi SQL Injection secara mendalam.

INTRUSIF: hanya dijalankan dengan --allow-intrusive DI STAGING. Flag dipilih agar
NON-DESTRUKTIF: tanpa --dump / ekstraksi data, tanpa stacked queries, level/risk
minimum. Menyasar HANYA endpoint dari endpoints-file (disiapkan manual penguji).

sqlmap tidak punya image Docker resmi, jadi adapter ini memakai binary `sqlmap`
yang terpasang lokal (dikontrol penguji di mesin staging).
"""

import re
import shutil
from typing import List, Optional

from src.adapters.base import ExternalAdapter, run_command
from src.core.endpoints import EndpointsConfig, INJECT_MARKER
from src.core.models import Finding, SOURCE_SQLMAP, SEVERITY_HIGH

_INJECTION_MARKERS = (
    "the following injection point",
    "is vulnerable",
    "sqlmap identified",
)


def parse_sqlmap_output(stdout: str, location: str) -> List[Finding]:
    """Deteksi konfirmasi injeksi dari stdout sqlmap."""
    if not stdout:
        return []
    low = stdout.lower()
    if not any(m in low for m in _INJECTION_MARKERS):
        return []

    params = re.findall(r"Parameter:\s*([^\s(]+)", stdout)
    param_str = ", ".join(sorted(set(params))) if params else "parameter tidak disebutkan"
    return [Finding(
        vulnerability=f"Confirmed SQL Injection ({param_str})",
        severity=SEVERITY_HIGH,
        location=location,
        evidence="sqlmap mengonfirmasi titik injeksi SQL (deteksi non-destruktif, tanpa ekstraksi data).",
        remediation="Gunakan parameterized query/ORM; validasi & sanitasi input di sisi server.",
        source=SOURCE_SQLMAP,
        wstg_ids=("WSTG-INPV-05",),
    )]


class SqlmapAdapter(ExternalAdapter):
    name = SOURCE_SQLMAP
    image = ""  # tidak pakai Docker
    intrusive = True
    timeout = 1200

    def __init__(self, endpoints: Optional[EndpointsConfig] = None):
        self.endpoints = endpoints

    def is_available(self) -> bool:
        return shutil.which("sqlmap") is not None

    def unavailable_reason(self) -> str:
        return "Binary 'sqlmap' tidak ditemukan di PATH."

    def _targets(self):
        """URL yang punya penanda {{INJECT}} dari endpoints-file."""
        if not self.endpoints:
            return []
        urls = []
        for t in self.endpoints.injection_tests:
            if INJECT_MARKER in t.get("body", {}).values() or INJECT_MARKER in t.get("query", {}).values():
                urls.append(t["url"])
        return urls

    def run(self, target: str) -> List[Finding]:
        findings: List[Finding] = []
        targets = self._targets() or [target]
        for url in targets:
            cmd = [
                "sqlmap", "-u", url,
                "--batch", "--level=1", "--risk=1",
                "--technique=BEUT",      # tanpa 'S' (stacked queries) -> non-destruktif
                "--flush-session",
                "--answers=quit=N",
            ]
            proc = run_command(cmd, self.timeout)
            if proc and proc.stdout:
                findings.extend(parse_sqlmap_output(proc.stdout, url))
        return findings
