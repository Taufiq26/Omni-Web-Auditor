"""Model & persistensi Engagement (satu audit = satu folder engagements/<nama>/).

State disimpan sebagai JSON (state.json) agar resumable. Berisi: metadata scope/RoE,
status tiap item checklist WSTG, daftar temuan, bukti (dengan hash), dan sign-off.
"""

import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

from src.core.models import Finding
from src.checklist.loader import load_checklist, ChecklistItem

# Status item checklist.
CHK_TODO = "todo"
CHK_PASS = "pass"
CHK_FAIL = "fail"
CHK_NA = "na"
CHK_SKIPPED = "skipped"
_VALID_CHK = {CHK_TODO, CHK_PASS, CHK_FAIL, CHK_NA, CHK_SKIPPED}

ENGAGEMENTS_DIR = "engagements"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Engagement:
    name: str
    target: str = ""
    scope: List[str] = field(default_factory=list)
    environment: str = "staging"          # staging | production
    tester_name: str = ""
    tester_role: str = "internal security assessment"
    intrusive: bool = False
    created_at: str = field(default_factory=_now)
    # item_states[id] = {status, note, auto, source, evidence:[{path,sha256,added_at,desc}]}
    item_states: Dict[str, dict] = field(default_factory=dict)
    findings: List[dict] = field(default_factory=list)
    coverage: List[dict] = field(default_factory=list)
    last_run_at: Optional[str] = None
    signoff: Optional[dict] = None

    # --- lokasi folder ---
    @staticmethod
    def dir_for(name: str) -> str:
        return os.path.join(ENGAGEMENTS_DIR, name)

    @property
    def dir(self) -> str:
        return self.dir_for(self.name)

    @property
    def state_path(self) -> str:
        return os.path.join(self.dir, "state.json")

    @property
    def evidence_dir(self) -> str:
        return os.path.join(self.dir, "evidence")

    # --- checklist ---
    def ensure_items(self, items: Optional[List[ChecklistItem]] = None) -> None:
        """Inisialisasi state untuk tiap item checklist yang belum ada."""
        items = items or load_checklist()
        for it in items:
            self.item_states.setdefault(
                it.id,
                {"status": CHK_TODO, "note": "", "auto": False, "source": "", "evidence": []},
            )

    def set_item(self, item_id: str, status: str, note: str = "", auto: bool = False,
                 source: str = "") -> None:
        if status not in _VALID_CHK:
            raise ValueError(f"Status item tidak valid: {status!r} (pilih {_VALID_CHK}).")
        state = self.item_states.setdefault(
            item_id, {"status": CHK_TODO, "note": "", "auto": False, "source": "", "evidence": []}
        )
        state["status"] = status
        if note:
            state["note"] = note
        state["auto"] = auto
        if source:
            state["source"] = source

    def add_evidence_ref(self, item_id: str, ref: dict) -> None:
        state = self.item_states.setdefault(
            item_id, {"status": CHK_TODO, "note": "", "auto": False, "source": "", "evidence": []}
        )
        state["evidence"].append(ref)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(asdict(finding))

    def replace_findings(self, findings: List[Finding]) -> None:
        self.findings = [asdict(f) for f in findings]

    # --- persistensi ---
    def save(self) -> None:
        os.makedirs(self.evidence_dir, exist_ok=True)
        with open(self.state_path, "w", encoding="utf-8") as f:
            json.dump(asdict(self), f, indent=2, ensure_ascii=False)

    @classmethod
    def load(cls, name: str) -> "Engagement":
        path = os.path.join(cls.dir_for(name), "state.json")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Engagement '{name}' tidak ditemukan ({path}).")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(**data)

    @classmethod
    def exists(cls, name: str) -> bool:
        return os.path.exists(os.path.join(cls.dir_for(name), "state.json"))
