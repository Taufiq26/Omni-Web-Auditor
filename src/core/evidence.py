"""Penyimpanan bukti dengan integritas (hash SHA-256 + timestamp) & redaksi.

Bukti disalin ke engagements/<nama>/evidence/ lalu di-hash supaya ada jejak audit
yang tidak mudah dibantah. Header sensitif (Authorization/Cookie) disensor sebelum
request/response disimpan sebagai bukti.
"""

import hashlib
import os
import re
import shutil
from datetime import datetime, timezone
from typing import Dict

_SENSITIVE_HEADER_RE = re.compile(
    r"(?im)^(Authorization|Cookie|Set-Cookie|X-Api-Key|X-Auth-Token)\s*:\s*.*$"
)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def redact_sensitive(text: str) -> str:
    """Sensor nilai header sensitif pada teks request/response."""
    return _SENSITIVE_HEADER_RE.sub(lambda m: f"{m.group(1)}: [REDACTED]", text)


def store_evidence(evidence_dir: str, src_path: str, desc: str = "") -> Dict:
    """Salin file bukti ke evidence_dir, hash, dan kembalikan referensinya.

    Nama file disimpan apa adanya; bila bentrok, ditambah prefix timestamp.
    """
    if not os.path.exists(src_path):
        raise FileNotFoundError(f"File bukti tidak ditemukan: {src_path}")
    os.makedirs(evidence_dir, exist_ok=True)

    base = os.path.basename(src_path)
    dest = os.path.join(evidence_dir, base)
    if os.path.exists(dest):
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        dest = os.path.join(evidence_dir, f"{stamp}_{base}")

    shutil.copy2(src_path, dest)
    return {
        "path": os.path.relpath(dest, start=os.path.dirname(evidence_dir)),
        "sha256": sha256_file(dest),
        "added_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "desc": desc,
    }


def store_text_evidence(evidence_dir: str, filename: str, text: str, desc: str = "") -> Dict:
    """Simpan bukti berbentuk teks (mis. request/response) dengan redaksi sensitif."""
    os.makedirs(evidence_dir, exist_ok=True)
    dest = os.path.join(evidence_dir, filename)
    if os.path.exists(dest):
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        dest = os.path.join(evidence_dir, f"{stamp}_{filename}")
    with open(dest, "w", encoding="utf-8") as f:
        f.write(redact_sensitive(text))
    return {
        "path": os.path.relpath(dest, start=os.path.dirname(evidence_dir)),
        "sha256": sha256_file(dest),
        "added_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "desc": desc,
    }
