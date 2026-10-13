import argparse

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Omni-Web-Auditor: Security Auditor CLI")
    
    parser.add_argument(
        "--target",
        required=True,
        help="URL atau IP address target (contoh: https://kotabaruparahyangan.com atau 192.168.1.100)"
    )
    
    parser.add_argument(
        "--scan-type",
        required=True,
        choices=['web', 'infra', 'full'],
        help="Pilihan tipe scan"
    )
    
    parser.add_argument(
        "--cookie",
        required=False,
        help="String session cookie untuk audit terautentikasi"
    )
    
    parser.add_argument(
        "--token",
        required=False,
        help="String Bearer token untuk audit API terautentikasi"
    )
    
    parser.add_argument(
        "--output",
        required=False,
        default="report_target.pdf",
        help="Nama file laporan (default: report_target.pdf)"
    )

    parser.add_argument(
        "--endpoints-file",
        required=False,
        help="Path file JSON berisi endpoint uji (SQLi/XSS body & IDOR dua-akun) "
             "yang DISIAPKAN MANUAL penguji. Lihat docs/07-perbaikan-cakupan-scan.md."
    )

    parser.add_argument(
        "--origin-ip",
        required=False,
        help="IP origin server asli untuk target di balik CDN/WAF. Isi HANYA jika kamu "
             "punya izin/akses langsung ke server tsb (tool tidak pernah menebak IP origin)."
    )

    # Kredensial dua-akun untuk uji IDOR/BOLA berbasis UUID (akun uji milik penguji).
    parser.add_argument("--token-a", required=False, help="Bearer token akun uji A (pemilik objek).")
    parser.add_argument("--token-b", required=False, help="Bearer token akun uji B (penyerang).")
    parser.add_argument("--cookie-a", required=False, help="Session cookie akun uji A (pemilik objek).")
    parser.add_argument("--cookie-b", required=False, help="Session cookie akun uji B (penyerang).")

    return parser.parse_args()
