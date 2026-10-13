"""Penegakan scope (Rules of Engagement) oleh kode, bukan hanya dokumen.

Prinsip #7 (docs/08): setiap request keluar wajib divalidasi terhadap daftar
host/IP yang diizinkan. Request ke luar scope DITOLAK (ScopeError) dan dicatat,
supaya tool tidak pernah menyentuh pihak ketiga di luar izin -- bahkan karena bug.
"""

from dataclasses import dataclass, field
from typing import FrozenSet, Optional
from urllib.parse import urlparse


class ScopeError(Exception):
    """Dilempar saat sebuah target berada di luar scope yang diizinkan."""


def _host_of(target: str) -> Optional[str]:
    """Ambil hostname/IP dari URL atau host polos. None bila tak bisa ditentukan."""
    if not target:
        return None
    parsed = urlparse(target if "://" in target else f"//{target}", scheme="")
    host = parsed.hostname
    if not host:
        # fallback untuk input seperti "example.com:443/path"
        host = target.split("/")[0].split(":")[0]
    return host.lower() if host else None


@dataclass(frozen=True)
class Scope:
    """Daftar host/IP yang boleh diuji.

    Args:
        hosts: hostname atau IP yang diizinkan (dibandingkan case-insensitive).
        allow_subdomains: bila True, subdomain dari host yang terdaftar juga diizinkan
            (mis. "storage.example.com" diizinkan bila "example.com" terdaftar).
    """
    hosts: FrozenSet[str] = field(default_factory=frozenset)
    allow_subdomains: bool = True

    @classmethod
    def from_list(cls, hosts, allow_subdomains: bool = True) -> "Scope":
        normalized = frozenset(h.strip().lower() for h in hosts if h and h.strip())
        return cls(hosts=normalized, allow_subdomains=allow_subdomains)

    def is_in_scope(self, target: str) -> bool:
        host = _host_of(target)
        if not host:
            return False
        if host in self.hosts:
            return True
        if self.allow_subdomains:
            return any(host.endswith(f".{allowed}") for allowed in self.hosts)
        return False

    def require(self, target: str) -> None:
        """Lempar ScopeError bila target di luar scope."""
        if not self.is_in_scope(target):
            raise ScopeError(
                f"Target di luar scope: {_host_of(target)!r}. "
                f"Host yang diizinkan: {sorted(self.hosts)}."
            )
