"""Utilitas pendukung pengujian IDOR/BOLA.

Dipakai oleh src/modules/active_scan.py. Dipisah ke modul sendiri supaya logika
murni (regex & perbandingan) mudah diuji unit tanpa jaringan.

Catatan etika (docs/07-perbaikan-cakupan-scan.md, Masalah #2):
- UUID itu *by design* tidak berurutan/predictable -> strategi tebak "ID+1" tidak
  berlaku untuk UUID. Mendeteksi UUID hanya menandai bahwa IDOR perlu diuji dengan
  metode dua-akun, BUKAN dengan menebak.
- Perbandingan respons di sini hanya untuk memperkuat *bukti non-destruktif*
  (membedakan 200-berisi-data vs 200-generik/not-found), bukan untuk eksfiltrasi.
"""

import re
from difflib import SequenceMatcher

# UUID v4 (format kanonik 8-4-4-4-12, hex). Dipakai untuk mengenali ID non-numerik.
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def is_uuid(value: str) -> bool:
    """True jika `value` berbentuk UUID kanonik."""
    return bool(UUID_PATTERN.match(value.strip())) if value else False


def response_similarity(text_a: str, text_b: str) -> float:
    """Rasio kemiripan dua body respons (0.0..1.0).

    Dipakai untuk membedakan: dua respons 200 yang isinya sama persis (kemungkinan
    halaman generik/template, BUKAN bukti IDOR) vs isi yang berbeda (lebih mungkin
    data objek berbeda). Dibatasi agar tidak memproses body raksasa.
    """
    if text_a is None or text_b is None:
        return 0.0
    limit = 20000  # cukup untuk perbandingan struktur, hemat CPU
    return SequenceMatcher(None, text_a[:limit], text_b[:limit]).ratio()
