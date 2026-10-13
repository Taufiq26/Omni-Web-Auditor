"""Adapter nuclei (ProjectDiscovery) — deteksi CVE, misconfig, exposures.

Non-intrusif secara default: tag berbahaya (intrusive/dos/fuzz) dikecualikan dan
rate limit dipasang. Memperluas cakupan 'exposed files/components' dari sekadar 6
path native menjadi ribuan template komunitas.
"""

import json
from typing import List

from src.adapters.base import ExternalAdapter, run_command, dockerized_target
from src.core.models import (
    Finding, SOURCE_NUCLEI,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO,
)

_SEVERITY_MAP = {
    "critical": SEVERITY_CRITICAL,
    "high": SEVERITY_HIGH,
    "medium": SEVERITY_MEDIUM,
    "low": SEVERITY_LOW,
    "info": SEVERITY_INFO,
    "unknown": SEVERITY_INFO,
}


def parse_nuclei_jsonl(output: str) -> List[Finding]:
    """Parse output nuclei -jsonl (satu objek JSON per baris) menjadi Finding."""
    findings: List[Finding] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = obj.get("info", {})
        severity = _SEVERITY_MAP.get(str(info.get("severity", "info")).lower(), SEVERITY_INFO)
        name = info.get("name") or obj.get("template-id", "nuclei finding")
        location = obj.get("matched-at") or obj.get("host", "")
        template_id = obj.get("template-id", "")

        remediation = info.get("remediation") or "Tinjau detail template nuclei & patch komponen terkait."
        classification = info.get("classification", {}) or {}
        cve_ids = classification.get("cve-id") or []
        cve_str = f" ({', '.join(cve_ids)})" if cve_ids else ""

        findings.append(Finding(
            vulnerability=f"{name}{cve_str}",
            severity=severity,
            location=location,
            evidence=f"nuclei template '{template_id}' cocok. {info.get('description', '')}".strip(),
            remediation=remediation,
            source=SOURCE_NUCLEI,
        ))
    return findings


class NucleiAdapter(ExternalAdapter):
    name = SOURCE_NUCLEI
    image = "projectdiscovery/nuclei:latest"
    intrusive = False
    timeout = 900

    def __init__(self, intrusive: bool = False):
        # Non-intrusif: HANYA template HTTP terhadap URL target. Template network
        # (tcp) seperti "Redis default login"/"Postgres default login" melakukan
        # port-probing & credential testing ke seluruh host -> itu memperluas scope
        # di luar URL target dan bersifat intrusif. Hanya diaktifkan bila intrusive.
        self.intrusive = intrusive

    def run(self, target: str) -> List[Finding]:
        tgt = dockerized_target(target)
        cmd = [
            "docker", "run", "--rm", "--add-host=host.docker.internal:host-gateway",
            self.image,
            "-u", tgt,
            "-jsonl",
            "-silent",
            "-rate-limit", "50",
            "-timeout", "10",
            "-exclude-tags", "intrusive,dos,fuzz",
        ]
        if not self.intrusive:
            # Batasi ke template HTTP saja -> tidak menyentuh port/servis lain di host.
            cmd += ["-type", "http"]
        proc = run_command(cmd, self.timeout)
        if proc is None or not proc.stdout:
            return []
        return parse_nuclei_jsonl(proc.stdout)
