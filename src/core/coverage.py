"""Pelacakan cakupan scan (scan coverage).

Modul ini memisahkan "apa yang ditemukan" (findings) dari "apa yang benar-benar
diuji" (coverage). Tujuannya menjaga kejujuran laporan: sebuah tes yang DILEWATI
tidak boleh tampil seolah target "aman", melainkan harus tercatat sebagai
"belum teruji" (lihat docs/07-perbaikan-cakupan-scan.md, prinsip #6).

Entri coverage sengaja berupa dict (konsisten dengan format findings antar modul)
dan selalu dibuat sebagai objek baru (immutable-friendly, tidak memutasi input).
"""

from src.core.models import CoverageEntry

# Status cakupan sebuah pengujian.
STATUS_TESTED = "TESTED"              # tes benar-benar dijalankan terhadap target
STATUS_SKIPPED = "SKIPPED"           # tes relevan TAPI tidak dijalankan (belum teruji)
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"  # tes memang tidak berlaku untuk target ini


def coverage_entry(test: str, status: str, detail: str) -> CoverageEntry:
    """Buat satu entri coverage baru (objek baru, tidak memutasi apa pun).

    Args:
        test: nama pengujian, mis. "IDOR/BOLA (API)".
        status: salah satu dari STATUS_TESTED/STATUS_SKIPPED/STATUS_NOT_APPLICABLE.
        detail: penjelasan singkat & jujur mengapa statusnya demikian.
    """
    valid = {STATUS_TESTED, STATUS_SKIPPED, STATUS_NOT_APPLICABLE}
    if status not in valid:
        raise ValueError(f"Status coverage tidak valid: {status!r} (harus salah satu dari {valid})")
    return CoverageEntry(test=test, status=status, detail=detail)
