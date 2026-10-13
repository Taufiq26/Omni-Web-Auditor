"""Adapter testssl.sh — audit TLS menyeluruh (protokol & cipher yang DITERIMA,
sertifikat, kerentanan seperti ROBOT/Heartbleed).

Menggantikan keterbatasan native yang hanya melihat protokol yang dinegosiasikan.
"""

import json
import os
import tempfile
from typing import List
from urllib.parse import urlparse

from src.adapters.base import ExternalAdapter, run_command, dockerized_target
from src.core.models import (
    Finding, SOURCE_TESTSSL,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW,
)

# Hanya severity yang menandakan masalah nyata yang dijadikan Finding.
_SEVERITY_MAP = {
    "CRITICAL": SEVERITY_CRITICAL,
    "HIGH": SEVERITY_HIGH,
    "MEDIUM": SEVERITY_MEDIUM,
    "LOW": SEVERITY_LOW,
}


def parse_testssl_json(output: str) -> List[Finding]:
    """Parse JSON testssl menjadi Finding (abaikan entri OK/INFO/WARN/DEBUG)."""
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []

    # Format bisa berupa list datar, atau objek dgn key "scanResult".
    if isinstance(data, dict):
        data = data.get("scanResult") or []
        if isinstance(data, list) and data and isinstance(data[0], dict):
            # scanResult = [{"...": ..., "...": [entries]}] -> gabungkan semua entri
            merged = []
            for block in data:
                for v in block.values():
                    if isinstance(v, list):
                        merged.extend(v)
            data = merged

    findings: List[Finding] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        sev = str(entry.get("severity", "")).upper()
        mapped = _SEVERITY_MAP.get(sev)
        if not mapped:
            continue
        test_id = entry.get("id", "tls")
        finding_text = entry.get("finding", "")
        cve = entry.get("cve", "")
        cve_str = f" ({cve})" if cve else ""
        findings.append(Finding(
            vulnerability=f"TLS: {test_id}{cve_str}",
            severity=mapped,
            location=entry.get("ip", ""),
            evidence=finding_text,
            remediation="Perbaiki konfigurasi TLS (nonaktifkan protokol/cipher lemah, perbarui sertifikat).",
            source=SOURCE_TESTSSL,
            wstg_ids=("WSTG-CRYP-01",),
        ))
    return findings


class TestsslAdapter(ExternalAdapter):
    name = SOURCE_TESTSSL
    image = "drwetter/testssl.sh:latest"
    intrusive = False
    timeout = 600

    def run(self, target: str) -> List[Finding]:
        tgt = dockerized_target(target)
        parsed = urlparse(tgt if "://" in tgt else f"//{tgt}")
        host = parsed.hostname or tgt
        port = parsed.port or 443
        host_port = f"{host}:{port}"

        out_dir = tempfile.mkdtemp(prefix="testssl_")
        out_file = os.path.join(out_dir, "out.json")
        cmd = [
            "docker", "run", "--rm",
            "--add-host=host.docker.internal:host-gateway",
            "-v", f"{out_dir}:/out",
            self.image,
            "--jsonfile", "/out/out.json",
            "--quiet", "--warnings", "off",
            host_port,
        ]
        run_command(cmd, self.timeout)
        if not os.path.exists(out_file):
            return []
        with open(out_file, "r", encoding="utf-8") as f:
            return parse_testssl_json(f.read())
