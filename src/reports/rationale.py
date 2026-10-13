"""Penjelasan hasil pengujian untuk laporan (kenapa 'aman' berarti aman).

Dipakai PDFReportGenerator agar laporan tetap informatif & bisa jadi bukti
walau tidak ada kerentanan: setiap pengujian yang lulus disertai alasan singkat
mengapa aspek itu dianggap aman, dan dikaitkan ke temuan terkait bila ada.

Pemetaan berbasis kata kunci sengaja transparan & mudah dirawat; jika nama
pengujian atau judul temuan berubah, cukup perbarui map di sini.
"""

from typing import List, Dict

# Untuk tiap pengujian (key = substring nama test di coverage):
#   keywords : kata kunci untuk mengaitkan sebuah finding ke pengujian ini.
#   secure   : penjelasan kenapa, bila lulus, aspek ini dianggap aman.
_RATIONALE = {
    "Security headers": {
        "keywords": ["security header", "missing security"],
        "secure": "Semua header keamanan utama (HSTS, CSP, X-Frame-Options, "
                  "X-Content-Type-Options) sudah ada, sehingga browser menegakkan "
                  "proteksi terhadap clickjacking, MIME-sniffing, dan downgrade HTTPS.",
    },
    "SSL/TLS": {
        "keywords": ["ssl", "tls", "sertifikat", "certificate", "protokol"],
        "secure": "Sertifikat masih berlaku dan server memakai protokol modern "
                  "(TLS 1.2/1.3), sehingga komunikasi terenkripsi dengan baik dan "
                  "tidak rentan terhadap protokol usang.",
    },
    "Exposed sensitive files": {
        "keywords": ["exposed", "file", ".env", "git", "backup"],
        "secure": "Jalur file sensitif umum (.env, .git/config, backup, .DS_Store) "
                  "tidak dapat diakses publik, sehingga tidak ada kebocoran "
                  "kredensial/konfigurasi/kode sumber.",
    },
    "SQLi/XSS (query parameter)": {
        "keywords": ["sql injection", "xss"],
        "secure": "Penyisipan payload uji pada parameter query tidak memunculkan "
                  "pesan error database maupun pantulan skrip, indikasi input "
                  "divalidasi/di-escape dengan benar.",
    },
    "SQLi/XSS (body/JSON endpoint)": {
        "keywords": ["sql injection", "xss"],
        "secure": "Penyisipan payload uji pada body/parameter JSON endpoint tidak "
                  "memicu error database maupun reflection, indikasi input "
                  "divalidasi/di-escape di sisi server.",
    },
    "IDOR/BOLA (ID+1 sekuensial)": {
        "keywords": ["idor", "bola", "authorization", "otorisasi"],
        "secure": "Mengubah ID numerik ke objek lain tidak mengembalikan data milik "
                  "objek lain, indikasi kontrol otorisasi level objek diterapkan.",
    },
    "IDOR/BOLA (dua-akun UUID)": {
        "keywords": ["idor", "bola", "cross-account", "authorization", "otorisasi"],
        "secure": "Akun B tidak dapat mengakses objek milik akun A, indikasi "
                  "kepemilikan objek divalidasi terhadap identitas pemanggil.",
    },
    "Port/SSH scan": {
        "keywords": ["port", "ssh", "service", "database/service"],
        "secure": "Tidak ada port database/servis sensitif (MySQL, PostgreSQL, Redis, "
                  "MongoDB) yang terbuka ke publik dan versi SSH tidak usang.",
    },
    "Cloud storage misconfiguration": {
        "keywords": ["storage", "s3", "bucket", "drive"],
        "secure": "Tidak ditemukan bucket/object storage yang dapat di-listing publik "
                  "maupun link berbagi sensitif yang terekspos.",
    },
}

_GENERIC_SECURE = "Pengujian dijalankan dan tidak menemukan indikasi kelemahan pada aspek ini."


def _match(test_name: str):
    for key, val in _RATIONALE.items():
        if key in test_name:
            return val
    return None


def secure_reason(test_name: str) -> str:
    """Penjelasan singkat kenapa pengujian ini, bila lulus, dianggap aman."""
    val = _match(test_name)
    return val["secure"] if val else _GENERIC_SECURE


def count_related_findings(test_name: str, findings: List[Dict]) -> int:
    """Berapa temuan yang terkait dengan pengujian ini (berdasarkan kata kunci)."""
    val = _match(test_name)
    if not val:
        return 0
    keywords = val["keywords"]
    count = 0
    for f in findings:
        title = str(f.get("vulnerability", "")).lower()
        if any(kw in title for kw in keywords):
            count += 1
    return count
