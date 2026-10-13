"""Loader checklist WSTG dari YAML menjadi dataclass immutable."""

import os
from dataclasses import dataclass
from typing import List, Tuple

import yaml

TYPE_AUTO = "auto"
TYPE_MANUAL = "manual"
TYPE_HYBRID = "hybrid"
_VALID_TYPES = {TYPE_AUTO, TYPE_MANUAL, TYPE_HYBRID}

_DEFAULT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wstg.yaml")


@dataclass(frozen=True)
class ChecklistItem:
    id: str
    category: str
    title: str
    type: str
    objective: str
    steps: str
    sources: Tuple[str, ...] = ()

    @property
    def is_auto(self) -> bool:
        """Item yang statusnya bisa diisi otomatis oleh tool (auto atau hybrid)."""
        return self.type in (TYPE_AUTO, TYPE_HYBRID)


def _parse_item(raw: dict, index: int) -> ChecklistItem:
    for key in ("id", "category", "title", "type"):
        if not raw.get(key):
            raise ValueError(f"Item checklist #{index} tidak punya field '{key}'.")
    item_type = raw["type"]
    if item_type not in _VALID_TYPES:
        raise ValueError(f"Item {raw['id']} punya type tidak valid: {item_type!r}.")
    return ChecklistItem(
        id=raw["id"],
        category=raw["category"],
        title=raw["title"],
        type=item_type,
        objective=raw.get("objective", ""),
        steps=raw.get("steps", ""),
        sources=tuple(raw.get("sources", []) or []),
    )


def load_checklist(path: str = _DEFAULT_PATH) -> List[ChecklistItem]:
    """Baca & validasi checklist WSTG."""
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict) or "items" not in data:
        raise ValueError("Checklist YAML harus punya key 'items'.")
    items = [_parse_item(raw, i) for i, raw in enumerate(data["items"])]
    ids = [it.id for it in items]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"Ada ID checklist duplikat: {sorted(dupes)}")
    return items
