"""Isi otomatis status item checklist dari hasil scan.

Aturan (tidak menimpa penilaian manual penguji):
- Ada temuan OPEN yang ber-WSTG-id item ini  -> FAIL (auto).
- Tidak ada temuan & item auto/hybrid & minimal satu sumbernya benar-benar berjalan
  & uji intinya BENAR-BENAR dijalankan (lihat di bawah) -> PASS (auto).
- Selain itu dibiarkan / dikembalikan ke TODO (jujur: "belum teruji cukup").

Mencegah FALSE PASS: untuk sebagian item, "sumber berjalan" tidak cukup — uji intinya
bisa saja NOT_APPLICABLE/SKIPPED (mis. SQLi body tanpa endpoints-file, IDOR hanya 1 URL).
Item di _ITEM_CORE_COVERAGE hanya auto-PASS bila ada coverage uji-intinya ber-status
TESTED dan tidak ada yang SKIPPED. Bila tidak, status dikembalikan ke TODO.
"""

from typing import List, Optional, Set

from src.core.models import Finding, STATUS_OPEN, CoverageEntry
from src.core.coverage import STATUS_TESTED, STATUS_SKIPPED
from src.checklist.loader import ChecklistItem
from src.core.engagement import Engagement, CHK_TODO, CHK_PASS, CHK_FAIL

_ADAPTER_PREFIX = "Adapter: "

# Item yang auto-PASS-nya WAJIB didasari uji inti yang benar-benar TESTED.
# Nilai = substring (case-insensitive) nama entri coverage yang menjadi bukti uji inti.
_ITEM_CORE_COVERAGE = {
    "WSTG-INPV-05": ("SQLi",),            # SQL Injection
    "WSTG-INPV-01": ("XSS",),             # Reflected XSS
    "WSTG-INPV-12": ("Command", "Perintah"),  # Command Injection
    "WSTG-ATHZ-04": ("IDOR",),            # IDOR/BOLA
    "WSTG-APIT-01": ("IDOR",),            # API BOLA
}


def _adequately_tested(item_id: str, coverage: Optional[List[CoverageEntry]]) -> bool:
    """True bila uji inti item benar-benar dijalankan (>=1 TESTED, tak ada SKIPPED).

    Item tanpa aturan khusus (atau tanpa data coverage) -> True (pakai perilaku lama).
    """
    keys = _ITEM_CORE_COVERAGE.get(item_id)
    if not keys or coverage is None:
        return True
    matched = [c for c in coverage if any(k.lower() in c.test.lower() for k in keys)]
    if not matched:
        return False  # ada aturan tapi tak ada coverage sama sekali -> jangan PASS
    tested = any(c.status == STATUS_TESTED for c in matched)
    skipped = any(c.status == STATUS_SKIPPED for c in matched)
    return tested and not skipped


def sources_ran_from_coverage(coverage: List[CoverageEntry]) -> Set[str]:
    """Tentukan sumber yang benar-benar berjalan dari daftar coverage."""
    ran: Set[str] = set()
    for c in coverage:
        if c.status != STATUS_TESTED:
            continue
        if c.test.startswith(_ADAPTER_PREFIX):
            ran.add(c.test[len(_ADAPTER_PREFIX):].strip())
        else:
            ran.add("native")
    return ran


def _is_overridable(state: dict) -> bool:
    """Item boleh diisi otomatis hanya bila masih todo atau sebelumnya auto."""
    return state.get("status") == CHK_TODO or state.get("auto", False)


def autofill(engagement: Engagement, items: List[ChecklistItem],
             findings: List[Finding], sources_ran: Set[str],
             coverage: Optional[List[CoverageEntry]] = None) -> None:
    engagement.ensure_items(items)
    open_findings = [f for f in findings if f.status == STATUS_OPEN]

    for item in items:
        state = engagement.item_states[item.id]
        if not _is_overridable(state):
            continue  # hormati penilaian manual penguji

        related = [f for f in open_findings if item.id in f.wstg_ids]
        if related:
            engagement.set_item(
                item.id, CHK_FAIL, auto=True, source="auto",
                note=f"{len(related)} temuan terkait (lihat Findings).",
            )
        elif (item.is_auto and (set(item.sources) & sources_ran)
              and _adequately_tested(item.id, coverage)):
            ran = sorted(set(item.sources) & sources_ran)
            engagement.set_item(
                item.id, CHK_PASS, auto=True, source=",".join(ran),
                note=f"Tidak ada temuan dari sumber: {', '.join(ran)}.",
            )
        elif state.get("auto", False):
            # Sebelumnya auto-PASS tapi kini tak memenuhi kriteria (mis. uji inti
            # SKIPPED/NOT_APPLICABLE) -> kembalikan ke TODO secara jujur.
            engagement.set_item(
                item.id, CHK_TODO, auto=True, source="auto",
                note="Belum teruji cukup (uji inti SKIPPED/NOT_APPLICABLE atau sumber tak lengkap).",
            )
        # else: biarkan todo manual (sumber belum berjalan / item murni manual)
