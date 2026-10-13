"""Registry adapter tool eksternal."""

from typing import List, Optional

from src.adapters.base import ExternalAdapter
from src.adapters.testssl import TestsslAdapter
from src.adapters.nuclei import NucleiAdapter
from src.adapters.zap import ZapAdapter
from src.adapters.sqlmap import SqlmapAdapter


def default_adapters(intrusive: bool = False, endpoints=None) -> List[ExternalAdapter]:
    """Daftar adapter sesuai mode.

    Non-intrusif (default): testssl, nuclei, ZAP baseline (pasif).
    Intrusif (staging + --allow-intrusive): ZAP full (active) + sqlmap.
    """
    adapters: List[ExternalAdapter] = [
        TestsslAdapter(),
        NucleiAdapter(intrusive=intrusive),
        ZapAdapter(intrusive=intrusive),
    ]
    if intrusive:
        adapters.append(SqlmapAdapter(endpoints=endpoints))
    return adapters


def available_adapters(intrusive: bool = False, endpoints=None) -> List[ExternalAdapter]:
    """Hanya adapter yang siap pakai (docker aktif & image ada, atau binary ada)."""
    return [a for a in default_adapters(intrusive, endpoints) if a.is_available()]
