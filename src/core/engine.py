"""Orkestrator audit: menjalankan native checks + adapter eksternal, lalu dedup.

Dipakai oleh CLI (Fase 3) dan benchmark. Mengumpulkan findings + coverage dari
semua sumber, menegakkan scope, dan menandai adapter yang tidak tersedia sebagai
SKIPPED (jujur, bukan dianggap lulus).
"""

from dataclasses import dataclass
from typing import List, Optional, Tuple

from src.core.session import ScannerSession
from src.core.scope import Scope, ScopeError
from src.core.endpoints import EndpointsConfig
from src.core.models import Finding, CoverageEntry
from src.core.coverage import coverage_entry, STATUS_TESTED, STATUS_SKIPPED
from src.core.normalize import deduplicate
from src.modules.basic_scan import BasicScanner
from src.modules.active_scan import ActiveScanner
from src.modules.infra_scan import InfraScanner
from src.adapters import default_adapters
from src.core.logging_setup import get_logger

logger = get_logger(__name__)


@dataclass
class AuditConfig:
    target: str
    scan_type: str = "full"              # web | infra | full
    scope: Optional[Scope] = None
    endpoints: Optional[EndpointsConfig] = None
    cookie: Optional[str] = None
    token: Optional[str] = None
    cookie_a: Optional[str] = None
    token_a: Optional[str] = None
    cookie_b: Optional[str] = None
    token_b: Optional[str] = None
    origin_ip: Optional[str] = None
    intrusive: bool = False
    use_adapters: bool = True


def _build_session(cookie, token, scope) -> Optional[ScannerSession]:
    if not cookie and not token:
        return None
    return ScannerSession(cookie=cookie, bearer_token=token, scope=scope)


class AuditEngine:
    def __init__(self, config: AuditConfig):
        self.cfg = config
        self.findings: List[Finding] = []
        self.coverage: List[CoverageEntry] = []

    def _add_coverage(self, test, status, detail):
        self.coverage.append(coverage_entry(test, status, detail))

    def run(self) -> Tuple[List[Finding], List[CoverageEntry]]:
        cfg = self.cfg
        session = ScannerSession(cookie=cfg.cookie, bearer_token=cfg.token, scope=cfg.scope)
        session_a = _build_session(cfg.cookie_a, cfg.token_a, cfg.scope) or session
        session_b = _build_session(cfg.cookie_b, cfg.token_b, cfg.scope)

        if cfg.scan_type in ("web", "full"):
            self._run_native_web(session, session_a, session_b)
        if cfg.scan_type in ("infra", "full"):
            self._run_native_infra(session)

        if cfg.use_adapters:
            self._run_adapters()

        self.findings = deduplicate(self.findings)
        return self.findings, self.coverage

    def _run_native_web(self, session, session_a, session_b):
        cfg = self.cfg
        basic = BasicScanner(session)
        self.findings.extend(basic.run_scan(cfg.target))
        self.coverage.extend(basic.coverage)

        active = ActiveScanner(session_a, endpoints=cfg.endpoints, session_b=session_b)
        has_auth = bool(cfg.cookie or cfg.token or cfg.cookie_a or cfg.token_a)
        self.findings.extend(active.run_scan(cfg.target, has_auth=has_auth))
        self.coverage.extend(active.coverage)

    def _run_native_infra(self, session):
        infra = InfraScanner(session, origin_ip=self.cfg.origin_ip)
        self.findings.extend(infra.run_scan(self.cfg.target))
        self.coverage.extend(infra.coverage)

    def _run_adapters(self):
        cfg = self.cfg
        # Scope berlaku juga untuk adapter: jangan jalankan tool eksternal ke luar scope.
        if cfg.scope is not None:
            try:
                cfg.scope.require(cfg.target)
            except ScopeError as e:
                self._add_coverage("Adapter eksternal", STATUS_SKIPPED, f"Target di luar scope: {e}")
                return

        for adapter in default_adapters(intrusive=cfg.intrusive, endpoints=cfg.endpoints):
            label = f"Adapter: {adapter.name}"
            if not adapter.is_available():
                self._add_coverage(label, STATUS_SKIPPED, adapter.unavailable_reason())
                continue
            logger.info("Menjalankan adapter %s...", adapter.name)
            found = adapter.run(cfg.target)
            self.findings.extend(found)
            mode = "intrusif" if adapter.intrusive else "non-intrusif"
            self._add_coverage(label, STATUS_TESTED, f"Dijalankan ({mode}); {len(found)} temuan mentah.")
