"""Adapter OWASP ZAP.

- Mode baseline (default): spider + passive scan -> NON-intrusif.
- Mode full (butuh intrusive=True): active scan -> hanya untuk staging.
"""

import json
import os
import tempfile
from typing import List

from src.adapters.base import ExternalAdapter, run_command, dockerized_target
from src.core.models import (
    Finding, SOURCE_ZAP,
    SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO,
)

# riskcode ZAP: 0=info, 1=low, 2=medium, 3=high
_RISK_MAP = {
    "3": SEVERITY_HIGH,
    "2": SEVERITY_MEDIUM,
    "1": SEVERITY_LOW,
    "0": SEVERITY_INFO,
}

# Peta nama alert ZAP -> WSTG (kasar, untuk mapping checklist Fase 3).
_WSTG_HINTS = [
    ("sql injection", "WSTG-INPV-05"),
    ("cross site scripting", "WSTG-INPV-01"),
    ("xss", "WSTG-INPV-01"),
    ("content security policy", "WSTG-CONF-07"),
    ("x-frame-options", "WSTG-CLNT-09"),
    ("cookie", "WSTG-SESS-02"),
]


def _wstg_for(name: str):
    low = name.lower()
    return tuple(wid for kw, wid in _WSTG_HINTS if kw in low)


def parse_zap_json(output: str) -> List[Finding]:
    """Parse JSON report ZAP baseline/full menjadi Finding."""
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []

    findings: List[Finding] = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            severity = _RISK_MAP.get(str(alert.get("riskcode", "0")), SEVERITY_INFO)
            name = alert.get("name", "ZAP alert")
            instances = alert.get("instances", [])
            location = instances[0].get("uri", site.get("@name", "")) if instances else site.get("@name", "")
            desc = alert.get("desc", "")
            solution = alert.get("solution", "Tinjau rekomendasi ZAP.")
            findings.append(Finding(
                vulnerability=name,
                severity=severity,
                location=location,
                evidence=_strip_html(desc)[:500],
                remediation=_strip_html(solution)[:500],
                source=SOURCE_ZAP,
                wstg_ids=_wstg_for(name),
            ))
    return findings


def _strip_html(text: str) -> str:
    import re
    return re.sub(r"<[^>]+>", "", text or "").strip()


class ZapAdapter(ExternalAdapter):
    name = SOURCE_ZAP
    image = "zaproxy/zap-stable:latest"
    timeout = 1800

    def __init__(self, intrusive: bool = False):
        # intrusive=True -> active scan (zap-full-scan). Default baseline (pasif).
        self.intrusive = intrusive

    def run(self, target: str) -> List[Finding]:
        tgt = dockerized_target(target)
        out_dir = tempfile.mkdtemp(prefix="zap_")
        report = "report.json"
        script = "zap-full-scan.py" if self.intrusive else "zap-baseline.py"
        cmd = [
            "docker", "run", "--rm",
            "--add-host=host.docker.internal:host-gateway",
            "-v", f"{out_dir}:/zap/wrk/:rw",
            self.image,
            script, "-t", tgt, "-J", report, "-I",
        ]
        run_command(cmd, self.timeout)
        report_path = os.path.join(out_dir, report)
        if not os.path.exists(report_path):
            return []
        with open(report_path, "r", encoding="utf-8") as f:
            return parse_zap_json(f.read())
