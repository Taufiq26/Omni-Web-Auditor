"""Logika pencocokan temuan terhadap ground truth (murni, mudah diuji)."""

from typing import List
from src.core.models import Finding


def finding_matches(finding: Finding, patterns: List[str]) -> bool:
    """True bila finding cocok dengan salah satu pattern.

    Pattern yang diawali 'WSTG' dicocokkan ke finding.wstg_ids (persis, case-insensitive).
    Pattern lain dicocokkan sebagai substring ke judul vulnerability (case-insensitive).
    """
    title = finding.vulnerability.lower()
    wstg_upper = {w.upper() for w in finding.wstg_ids}
    for p in patterns:
        if p.upper().startswith("WSTG"):
            if p.upper() in wstg_upper:
                return True
        elif p.lower() in title:
            return True
    return False


def any_finding_matches(findings: List[Finding], patterns: List[str]) -> bool:
    return any(finding_matches(f, patterns) for f in findings)


def is_applicable(detectable_by: List[str], available_sources: List[str]) -> bool:
    """Item ground truth relevan bila ada irisan antara detectable_by & sumber tersedia."""
    return bool(set(detectable_by) & set(available_sources))
