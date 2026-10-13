"""Isi otomatis status item checklist dari hasil scan.

Aturan (tidak menimpa penilaian manual penguji):
- Ada temuan OPEN yang ber-WSTG-id item ini  -> FAIL (auto).
- Tidak ada temuan & item auto/hybrid & minimal satu sumbernya benar-benar berjalan
  -> PASS (auto).
- Selain itu dibiarkan (todo / manual / sumber tidak berjalan).
"""

from typing import List, Set

from src.core.models import Finding, STATUS_OPEN, CoverageEntry
from src.core.coverage import STATUS_TESTED
from src.checklist.loader import ChecklistItem
from src.core.engagement import Engagement, CHK_TODO, CHK_PASS, CHK_FAIL

_ADAPTER_PREFIX = "Adapter: "


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
             findings: List[Finding], sources_ran: Set[str]) -> None:
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
        elif item.is_auto and (set(item.sources) & sources_ran):
            ran = sorted(set(item.sources) & sources_ran)
            engagement.set_item(
                item.id, CHK_PASS, auto=True, source=",".join(ran),
                note=f"Tidak ada temuan dari sumber: {', '.join(ran)}.",
            )
        # else: biarkan todo (manual / sumber belum berjalan)
