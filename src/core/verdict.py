"""Mesin verdict: menentukan PASS / FAIL / INCOMPLETE untuk sebuah engagement.

Aturan (docs/08 §1):
- FAIL   : ada temuan Critical/High yang masih terbuka.
- PASS   : semua item relevan (non-NA) berstatus PASS & berbukti, tidak ada temuan
           Critical/High terbuka, temuan Medium terbuka semua risk-accepted, dan
           laporan sudah ditandatangani.
- INCOMPLETE: ada item relevan belum dikerjakan / bukti kurang / Medium belum
           di-accept / belum sign-off.

FAIL diprioritaskan di atas INCOMPLETE.
"""

from dataclasses import dataclass, field
from typing import List

from src.core.models import (
    Finding, severity_rank, SEVERITY_HIGH, SEVERITY_MEDIUM,
    STATUS_ACCEPTED, STATUS_FIXED, STATUS_FALSE_POSITIVE,
)
from src.checklist.loader import ChecklistItem, TYPE_MANUAL, TYPE_HYBRID
from src.core.engagement import Engagement, CHK_PASS, CHK_FAIL, CHK_NA, CHK_TODO, CHK_SKIPPED

# Status yang dianggap "tuntas" (tidak lagi menghambat verdict).
_RESOLVED = {STATUS_FIXED, STATUS_FALSE_POSITIVE}

VERDICT_PASS = "PASS"
VERDICT_FAIL = "FAIL"
VERDICT_INCOMPLETE = "INCOMPLETE"


@dataclass
class VerdictResult:
    status: str
    reasons: List[str] = field(default_factory=list)


def evaluate(engagement: Engagement, items: List[ChecklistItem], findings: List[Finding]) -> VerdictResult:
    unresolved = [f for f in findings if f.status not in _RESOLVED]

    # 1. FAIL bila ada Critical/High yang belum tuntas (accept TIDAK berlaku untuk High+).
    crit_high = [f for f in unresolved if severity_rank(f.severity) >= severity_rank(SEVERITY_HIGH)]
    if crit_high:
        reasons = [f"Temuan {f.severity} belum tuntas: {f.vulnerability}" for f in crit_high]
        return VerdictResult(VERDICT_FAIL, reasons)

    reasons: List[str] = []

    # 2. Item relevan belum selesai / bukti kurang.
    for item in items:
        state = engagement.item_states.get(item.id, {"status": CHK_TODO, "evidence": []})
        status = state.get("status", CHK_TODO)
        if status == CHK_NA:
            continue
        if status in (CHK_TODO, CHK_SKIPPED):
            reasons.append(f"Item {item.id} belum dikerjakan (status: {status}).")
            continue
        # Item manual/hybrid yang dinilai manual wajib ada bukti.
        is_manualish = item.type in (TYPE_MANUAL, TYPE_HYBRID)
        manually_set = not state.get("auto", False)
        if status in (CHK_PASS, CHK_FAIL) and is_manualish and manually_set and not state.get("evidence"):
            reasons.append(f"Item {item.id} berstatus {status} tanpa bukti terlampir.")

    # 3. Temuan Medium wajib risk-accepted (atau sudah tuntas).
    open_medium = [
        f for f in unresolved
        if severity_rank(f.severity) == severity_rank(SEVERITY_MEDIUM) and f.status != STATUS_ACCEPTED
    ]
    for f in open_medium:
        reasons.append(f"Temuan Medium belum di-accept/diperbaiki: {f.vulnerability}")

    # 4. Sign-off.
    if not engagement.signoff:
        reasons.append("Laporan belum ditandatangani (sign-off).")

    if reasons:
        return VerdictResult(VERDICT_INCOMPLETE, reasons)
    return VerdictResult(VERDICT_PASS, ["Semua item relevan PASS & berbukti, tidak ada temuan High+ terbuka, sign-off lengkap."])
