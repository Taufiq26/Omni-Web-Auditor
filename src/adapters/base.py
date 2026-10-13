"""Kontrak & utilitas untuk adapter tool eksternal (dijalankan via Docker).

Tiap adapter membungkus satu tool yang sudah teruji (testssl.sh, nuclei, ZAP,
sqlmap) dan menormalkan outputnya menjadi list[Finding]. Bila Docker/image tidak
tersedia, adapter melapor `is_available() == False` sehingga pengujiannya dicatat
sebagai coverage SKIPPED -- bukan dianggap lulus diam-diam (prinsip #9 docs/08).
"""

import shutil
import subprocess
from abc import ABC, abstractmethod
from typing import List, Optional
from urllib.parse import urlparse

from src.core.models import Finding
from src.core.logging_setup import get_logger

logger = get_logger(__name__)

# Default timeout per adapter (detik). Bisa dinaikkan per adapter bila perlu.
DEFAULT_TIMEOUT = 600


def docker_available() -> bool:
    """True bila CLI docker ada dan daemon merespons."""
    if shutil.which("docker") is None:
        return False
    try:
        r = subprocess.run(
            ["docker", "info"], capture_output=True, text=True, timeout=15
        )
        return r.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def image_present(image: str) -> bool:
    """True bila image Docker sudah ada secara lokal (tidak memicu pull)."""
    try:
        r = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True, text=True, timeout=30,
        )
        return r.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def dockerized_target(target: str) -> str:
    """Terjemahkan localhost -> host.docker.internal agar bisa dijangkau dari dalam
    container (Docker Desktop). Target publik tidak diubah."""
    parsed = urlparse(target if "://" in target else f"//{target}")
    host = parsed.hostname
    if host in ("localhost", "127.0.0.1"):
        return target.replace(host, "host.docker.internal")
    return target


def run_command(cmd: List[str], timeout: int) -> Optional[subprocess.CompletedProcess]:
    """Jalankan perintah eksternal dengan timeout. None bila gagal dijalankan/timeout."""
    logger.info("Menjalankan: %s", " ".join(cmd))
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.warning("Timeout (%ss) menjalankan: %s", timeout, cmd[0])
        return None
    except (subprocess.SubprocessError, OSError) as e:
        logger.warning("Gagal menjalankan %s: %s", cmd[0], e)
        return None


class ExternalAdapter(ABC):
    """Basis adapter tool eksternal."""

    #: nama sumber (harus cocok dengan nilai SOURCE_* & detectable_by di ground truth)
    name: str = "external"
    #: image Docker yang dipakai
    image: str = ""
    #: apakah adapter ini bersifat intrusif (butuh --allow-intrusive + staging)
    intrusive: bool = False
    #: timeout detik
    timeout: int = DEFAULT_TIMEOUT

    def is_available(self) -> bool:
        """Adapter siap dipakai bila docker aktif & image sudah ada lokal."""
        return docker_available() and image_present(self.image)

    @abstractmethod
    def run(self, target: str) -> List[Finding]:
        """Jalankan tool terhadap target & kembalikan temuan ternormalisasi."""
        raise NotImplementedError

    def unavailable_reason(self) -> str:
        if shutil.which("docker") is None or not docker_available():
            return "Docker tidak aktif/terpasang."
        if not image_present(self.image):
            return f"Image '{self.image}' belum ada lokal (jalankan: docker pull {self.image})."
        return "Tidak tersedia."
