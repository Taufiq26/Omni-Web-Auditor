"""Konfigurasi logging terpusat.

Mengganti print() dengan logging terstruktur: output ke konsol, dan opsional ke
file log per engagement sebagai bagian dari jejak audit (prinsip #6 docs/07).
"""

import logging
import sys
from typing import Optional

_CONSOLE_FORMAT = "[%(levelname)s] %(message)s"
_FILE_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

_configured = False


def configure_logging(level: int = logging.INFO, log_file: Optional[str] = None) -> None:
    """Pasang handler konsol (dan file, bila diberikan) pada root logger.

    Aman dipanggil berkali-kali: handler lama dibersihkan dulu agar tidak dobel.
    """
    global _configured
    root = logging.getLogger()
    root.setLevel(level)

    # Bersihkan handler lama supaya pemanggilan ulang tidak menduplikasi output.
    for handler in list(root.handlers):
        root.removeHandler(handler)

    console = logging.StreamHandler(stream=sys.stdout)
    console.setFormatter(logging.Formatter(_CONSOLE_FORMAT))
    root.addHandler(console)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(logging.Formatter(_FILE_FORMAT))
        root.addHandler(file_handler)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Ambil logger modul. Pasang konfigurasi default bila belum ada."""
    if not _configured:
        configure_logging()
    return logging.getLogger(name)
