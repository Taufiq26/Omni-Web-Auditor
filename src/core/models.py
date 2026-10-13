"""Model data ternormalisasi untuk temuan & cakupan.

Menggantikan dict bebas supaya struktur konsisten antar modul dan antar sumber
(native checks maupun tool eksternal seperti nuclei/ZAP/testssl). Semua immutable
(frozen) sesuai aturan coding-style: bangun objek baru, jangan mutasi.
"""

from dataclasses import dataclass, replace
from typing import Optional, Tuple

# --- Severity ---
SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"
SEVERITY_INFO = "Info"

# Urutan untuk sorting & agregasi (makin besar makin parah).
_SEVERITY_RANK = {
    SEVERITY_INFO: 0,
    SEVERITY_LOW: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_HIGH: 3,
    SEVERITY_CRITICAL: 4,
}

# --- Sumber temuan ---
SOURCE_NATIVE = "native"
SOURCE_NUCLEI = "nuclei"
SOURCE_ZAP = "zap"
SOURCE_TESTSSL = "testssl"
SOURCE_SQLMAP = "sqlmap"
SOURCE_MANUAL = "manual"

# --- Status siklus hidup temuan ---
STATUS_OPEN = "open"
STATUS_FIXED = "fixed"
STATUS_ACCEPTED = "accepted"          # risk accepted (ada alasan tertulis)
STATUS_FALSE_POSITIVE = "false_positive"


def severity_rank(severity: str) -> int:
    """Peringkat numerik severity (tak dikenal -> 0)."""
    return _SEVERITY_RANK.get(severity, 0)


@dataclass(frozen=True)
class Finding:
    """Satu temuan keamanan yang ternormalisasi (immutable)."""
    vulnerability: str
    severity: str
    location: str
    evidence: str
    remediation: str
    source: str = SOURCE_NATIVE
    wstg_ids: Tuple[str, ...] = ()
    cvss_vector: Optional[str] = None
    status: str = STATUS_OPEN

    def with_status(self, status: str, note: Optional[str] = None) -> "Finding":
        """Kembalikan salinan dengan status diperbarui (immutable)."""
        updated = replace(self, status=status)
        if note:
            updated = replace(updated, evidence=f"{updated.evidence}\n[catatan: {note}]")
        return updated

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        """Rekonstruksi Finding dari dict (mis. hasil persistensi JSON)."""
        allowed = {f for f in cls.__dataclass_fields__}
        kwargs = {k: v for k, v in data.items() if k in allowed}
        if "wstg_ids" in kwargs and kwargs["wstg_ids"] is not None:
            kwargs["wstg_ids"] = tuple(kwargs["wstg_ids"])
        return cls(**kwargs)


@dataclass(frozen=True)
class CoverageEntry:
    """Status cakupan satu pengujian (immutable)."""
    test: str
    status: str
    detail: str
