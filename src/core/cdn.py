"""Deteksi apakah target berada di belakang CDN/WAF (mis. Cloudflare).

Kenapa penting (docs/07-perbaikan-cakupan-scan.md, Masalah #3): kalau domain target
berada di belakang Cloudflare, IP hasil `socket.gethostbyname()` adalah milik
Cloudflare, BUKAN server asal. Memindai port/SSH ke IP itu berarti memindai
infrastruktur pihak ketiga di luar scope izin -- tidak akurat sekaligus melanggar
kode etik. Modul ini mendeteksi kondisi tersebut supaya scan infra bisa berhenti
dengan jujur, bukan diam-diam melaporkan "0 temuan = aman".
"""

import ipaddress
from typing import Optional, Mapping

# Range IP publik Cloudflare (sumber resmi: https://www.cloudflare.com/ips/).
# Dipakai untuk deteksi offline tanpa request tambahan.
CLOUDFLARE_IPV4_RANGES = (
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
)

# Header respons yang menandai Cloudflare (dibandingkan lowercase).
_CLOUDFLARE_HEADER_HINTS = ("cf-ray", "cf-cache-status", "cf-connecting-ip")


def ip_in_cloudflare_range(ip: str) -> bool:
    """True jika `ip` berada di salah satu range IP publik Cloudflare."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in CLOUDFLARE_IPV4_RANGES:
        try:
            if addr in ipaddress.ip_network(cidr):
                return True
        except ValueError:
            continue
    return False


def detect_cdn(ip: Optional[str] = None, headers: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """Deteksi CDN dari IP dan/atau header respons.

    Mengembalikan nama CDN (mis. "Cloudflare") bila terdeteksi, atau None.
    Deteksi bersifat non-destruktif: hanya membaca IP & header yang sudah ada.
    """
    if ip and ip_in_cloudflare_range(ip):
        return "Cloudflare"

    if headers:
        # requests.Response.headers bersifat case-insensitive, tapi jaga-jaga
        # kalau dipanggil dengan dict biasa -> normalisasi ke lowercase.
        lowered = {str(k).lower(): str(v).lower() for k, v in headers.items()}
        if lowered.get("server", "") == "cloudflare":
            return "Cloudflare"
        if any(hint in lowered for hint in _CLOUDFLARE_HEADER_HINTS):
            return "Cloudflare"

    return None
