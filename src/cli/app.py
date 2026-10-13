"""CLI `audit` — entry point tunggal Omni-Web-Auditor (menggantikan main.py lama).

Alur engagement: init -> run -> (checklist/mark/finding) -> verdict -> signoff -> report.
"""

import argparse
import os
import sys
from datetime import datetime, timezone
from typing import List, Optional

from urllib.parse import urlparse

from src.core.logging_setup import get_logger, configure_logging
from src.core.engagement import (
    Engagement, ENGAGEMENTS_DIR,
    CHK_TODO, CHK_PASS, CHK_FAIL, CHK_NA, CHK_SKIPPED,
)
from src.core.scope import Scope
from src.core.endpoints import load_endpoints_file
from src.core.engine import AuditEngine, AuditConfig
from src.core.models import (
    Finding, CoverageEntry,
    STATUS_OPEN, STATUS_FIXED, STATUS_ACCEPTED, STATUS_FALSE_POSITIVE,
)
from src.core.autofill import autofill, sources_ran_from_coverage
from src.core.verdict import evaluate
from src.core.evidence import store_evidence
from src.checklist.loader import load_checklist

logger = get_logger("audit")

_FINDING_STATUSES = {STATUS_OPEN, STATUS_FIXED, STATUS_ACCEPTED, STATUS_FALSE_POSITIVE}


# ----------------------------- util -----------------------------

def _host_of(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"//{target}")
    return (parsed.hostname or target).lower()


def _list_engagement_names() -> List[str]:
    if not os.path.isdir(ENGAGEMENTS_DIR):
        return []
    return sorted(
        d for d in os.listdir(ENGAGEMENTS_DIR)
        if os.path.exists(os.path.join(ENGAGEMENTS_DIR, d, "state.json"))
    )


def _resolve_name(name: Optional[str]) -> str:
    if name:
        return name
    names = _list_engagement_names()
    if len(names) == 1:
        return names[0]
    if not names:
        _fail("Belum ada engagement. Buat dengan: audit init <nama> --target <url>")
    _fail(f"Ada beberapa engagement; sebutkan namanya. Pilihan: {', '.join(names)}")


def _fail(msg: str) -> None:
    logger.error(msg)
    sys.exit(1)


# ----------------------------- commands -----------------------------

def cmd_init(args) -> None:
    if Engagement.exists(args.name):
        _fail(f"Engagement '{args.name}' sudah ada.")
    scope = args.scope or [_host_of(args.target)]
    eng = Engagement(
        name=args.name,
        target=args.target,
        scope=scope,
        environment=args.environment,
        tester_name=args.tester or "",
        tester_role=args.role,
        intrusive=args.intrusive,
    )
    eng.ensure_items()
    eng.save()
    logger.info("Engagement '%s' dibuat di %s", args.name, eng.dir)
    logger.info("Target: %s | scope: %s | environment: %s", args.target, scope, args.environment)
    logger.info("Langkah berikutnya: audit run %s", args.name)


def cmd_run(args) -> None:
    eng = Engagement.load(_resolve_name(args.name))

    if args.allow_intrusive and eng.environment == "production":
        _fail("Mode intrusif DITOLAK di environment production. Hanya boleh di staging.")
    intrusive = args.allow_intrusive and eng.intrusive and eng.environment == "staging"
    if args.allow_intrusive and not intrusive:
        logger.warning("Mode intrusif tidak aktif (butuh engagement --intrusive & environment staging).")

    endpoints = None
    if args.endpoints_file:
        try:
            endpoints = load_endpoints_file(args.endpoints_file)
        except ValueError as e:
            _fail(f"Gagal memuat --endpoints-file: {e}")

    config = AuditConfig(
        target=eng.target,
        scan_type=args.scan_type,
        scope=Scope.from_list(eng.scope),
        endpoints=endpoints,
        cookie=args.cookie, token=args.token,
        cookie_a=args.cookie_a, token_a=args.token_a,
        cookie_b=args.cookie_b, token_b=args.token_b,
        origin_ip=args.origin_ip,
        intrusive=intrusive,
        use_adapters=not args.no_adapters,
    )
    logger.info("Menjalankan audit untuk '%s' (intrusif=%s)...", eng.name, intrusive)
    findings, coverage = AuditEngine(config).run()

    eng.replace_findings(findings)
    eng.coverage = [vars(c) for c in coverage]
    eng.last_run_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    items = load_checklist()
    autofill(eng, items, findings, sources_ran_from_coverage(coverage))
    eng.save()

    logger.info("Selesai: %d temuan, %d entri coverage.", len(findings), len(coverage))
    _print_verdict(eng, items, findings)


def cmd_checklist(args) -> None:
    eng = Engagement.load(_resolve_name(args.name))
    items = load_checklist()
    print(f"\nChecklist WSTG — engagement '{eng.name}'")
    print("-" * 78)
    for it in items:
        st = eng.item_states.get(it.id, {"status": CHK_TODO})
        status = st.get("status", CHK_TODO)
        if args.status and status != args.status:
            continue
        auto = " (auto)" if st.get("auto") else ""
        print(f"  [{status.upper():<8}] {it.id:<14} {it.title}{auto}")
    print("-" * 78)


def cmd_mark(args) -> None:
    eng = Engagement.load(_resolve_name(args.name))
    items = {it.id for it in load_checklist()}
    if args.item_id not in items:
        _fail(f"Item '{args.item_id}' tidak ada di checklist.")
    evidence_refs = []
    for path in args.evidence or []:
        try:
            ref = store_evidence(eng.evidence_dir, path, desc=args.note or "")
            evidence_refs.append(ref)
        except FileNotFoundError as e:
            _fail(str(e))
    eng.set_item(args.item_id, args.status, note=args.note or "", auto=False, source="manual")
    for ref in evidence_refs:
        eng.add_evidence_ref(args.item_id, ref)
    eng.save()
    logger.info("Item %s -> %s (%d bukti).", args.item_id, args.status, len(evidence_refs))


def cmd_findings(args) -> None:
    eng = Engagement.load(_resolve_name(args.name))
    if not eng.findings:
        print("Belum ada temuan. Jalankan: audit run")
        return
    print(f"\nTemuan — engagement '{eng.name}'")
    print("-" * 78)
    for i, f in enumerate(eng.findings):
        print(f"  [{i}] {f.get('severity','?'):<8} {f.get('status','open'):<14} {f.get('vulnerability','')}")
    print("-" * 78)


def cmd_finding(args) -> None:
    eng = Engagement.load(_resolve_name(args.name))
    if not (0 <= args.index < len(eng.findings)):
        _fail(f"Index temuan di luar rentang (0..{len(eng.findings)-1}).")
    if args.status not in _FINDING_STATUSES:
        _fail(f"Status temuan tidak valid: {args.status}")
    eng.findings[args.index]["status"] = args.status
    if args.note:
        eng.findings[args.index]["evidence"] = (
            f"{eng.findings[args.index].get('evidence','')}\n[catatan: {args.note}]"
        )
    eng.save()
    logger.info("Temuan #%d -> %s", args.index, args.status)


def cmd_verdict(args) -> None:
    eng = Engagement.load(_resolve_name(args.name))
    items = load_checklist()
    findings = [Finding.from_dict(f) for f in eng.findings]
    _print_verdict(eng, items, findings)


def cmd_signoff(args) -> None:
    eng = Engagement.load(_resolve_name(args.name))
    eng.signoff = {
        "name": args.name_signer,
        "role": eng.tester_role,
        "statement": args.statement,
        "signed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    eng.save()
    logger.info("Sign-off tercatat atas nama '%s'.", args.name_signer)


def cmd_report(args) -> None:
    eng = Engagement.load(_resolve_name(args.name))
    from src.reports.pentest_report import generate_pentest_report
    items = load_checklist()
    findings = [Finding.from_dict(f) for f in eng.findings]
    coverage = [CoverageEntry(**c) for c in eng.coverage]
    verdict = evaluate(eng, items, findings)
    out = args.output or os.path.join(eng.dir, f"pentest_report_{eng.name}.pdf")
    generate_pentest_report(eng, items, findings, coverage, verdict, out)
    logger.info("Laporan dibuat: %s", out)


# ----------------------------- shared -----------------------------

def _print_verdict(eng: Engagement, items, findings) -> None:
    result = evaluate(eng, items, findings)
    print(f"\n=== VERDICT: {result.status} (WSTG-based self-assessment) ===")
    for r in result.reasons[:12]:
        print(f"  - {r}")
    if result.status != "PASS":
        print("  (lengkapi item/temuan di atas, lalu jalankan audit verdict lagi)")
    print()


# ----------------------------- parser -----------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="audit", description="Omni-Web-Auditor — WSTG-based security assessment")
    sub = p.add_subparsers(dest="command", required=True)

    pi = sub.add_parser("init", help="Buat engagement baru")
    pi.add_argument("name")
    pi.add_argument("--target", required=True)
    pi.add_argument("--scope", nargs="+", help="Host/IP yang diizinkan (default: host target)")
    pi.add_argument("--environment", choices=["staging", "production"], default="staging")
    pi.add_argument("--tester", help="Nama penguji")
    pi.add_argument("--role", default="internal security assessment")
    pi.add_argument("--intrusive", action="store_true", help="Izinkan mode intrusif (staging)")
    pi.set_defaults(func=cmd_init)

    pr = sub.add_parser("run", help="Jalankan scan (native + adapter)")
    pr.add_argument("name", nargs="?")
    pr.add_argument("--scan-type", choices=["web", "infra", "full"], default="full")
    pr.add_argument("--endpoints-file")
    pr.add_argument("--cookie")
    pr.add_argument("--token")
    pr.add_argument("--cookie-a")
    pr.add_argument("--token-a")
    pr.add_argument("--cookie-b")
    pr.add_argument("--token-b")
    pr.add_argument("--origin-ip")
    pr.add_argument("--allow-intrusive", action="store_true")
    pr.add_argument("--no-adapters", action="store_true", help="Lewati adapter eksternal")
    pr.set_defaults(func=cmd_run)

    pc = sub.add_parser("checklist", help="Tampilkan checklist WSTG")
    pc.add_argument("name", nargs="?")
    pc.add_argument("--status", choices=[CHK_TODO, CHK_PASS, CHK_FAIL, CHK_NA, CHK_SKIPPED])
    pc.set_defaults(func=cmd_checklist)

    pm = sub.add_parser("mark", help="Tandai status item checklist (manual)")
    pm.add_argument("item_id")
    pm.add_argument("--name", help="Nama engagement")
    pm.add_argument("--status", required=True, choices=[CHK_PASS, CHK_FAIL, CHK_NA, CHK_SKIPPED, CHK_TODO])
    pm.add_argument("--note")
    pm.add_argument("--evidence", action="append", help="File bukti (boleh berkali-kali)")
    pm.set_defaults(func=cmd_mark)

    pf = sub.add_parser("findings", help="Daftar temuan")
    pf.add_argument("name", nargs="?")
    pf.set_defaults(func=cmd_findings)

    pfs = sub.add_parser("finding", help="Ubah status satu temuan")
    pfs.add_argument("index", type=int)
    pfs.add_argument("--name")
    pfs.add_argument("--status", required=True, choices=sorted(_FINDING_STATUSES))
    pfs.add_argument("--note")
    pfs.set_defaults(func=cmd_finding)

    pv = sub.add_parser("verdict", help="Hitung verdict PASS/FAIL/INCOMPLETE")
    pv.add_argument("name", nargs="?")
    pv.set_defaults(func=cmd_verdict)

    ps = sub.add_parser("signoff", help="Tandatangani laporan")
    ps.add_argument("name", nargs="?")
    ps.add_argument("--name-signer", required=True, help="Nama penandatangan")
    ps.add_argument("--statement", default="Saya menyatakan hasil asesmen ini benar sesuai metodologi WSTG.")
    ps.set_defaults(func=cmd_signoff)

    prp = sub.add_parser("report", help="Hasilkan laporan PDF")
    prp.add_argument("name", nargs="?")
    prp.add_argument("--output")
    prp.set_defaults(func=cmd_report)

    return p


def main(argv=None) -> None:
    configure_logging()
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
