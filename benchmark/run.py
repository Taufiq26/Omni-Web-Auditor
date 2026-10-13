"""Benchmark harness: ukur recall & false-positive tool terhadap lab ber-ground-truth.

Jalankan (setelah `docker compose -f benchmark/docker-compose.yml up -d`):
    python -m benchmark.run                 # jalankan & cetak metrik
    python -m benchmark.run --baseline      # simpan juga sebagai results/baseline.json

Membandingkan temuan tool dengan benchmark/ground_truth.yaml, lalu melaporkan:
- recall per target (berapa % celah yang applicable berhasil ditangkap)
- false-positive pada target "bersih"
- durasi scan
"""

import argparse
import datetime
import json
import os
import time
from typing import List, Dict

import yaml

from src.core.models import Finding, severity_rank, SEVERITY_MEDIUM
from src.core.session import ScannerSession
from src.modules.basic_scan import BasicScanner
from src.modules.active_scan import ActiveScanner
from src.core.normalize import deduplicate
from src.adapters import available_adapters
from src.core.logging_setup import get_logger

logger = get_logger("benchmark")

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(HERE, "results")


def available_sources(intrusive: bool = False) -> List[str]:
    """Sumber deteksi yang tersedia: native + adapter eksternal yang siap pakai."""
    sources = ["native"]
    sources.extend(a.name for a in available_adapters(intrusive=intrusive))
    return sources


def scan_target(url: str, intrusive: bool = False) -> List[Finding]:
    """Jalankan native web checks + adapter eksternal yang tersedia, lalu dedup."""
    session = ScannerSession()
    findings: List[Finding] = []
    findings.extend(BasicScanner(session).run_scan(url))
    findings.extend(ActiveScanner(session).run_scan(url, has_auth=False))
    for adapter in available_adapters(intrusive=intrusive):
        logger.info("  adapter %s ...", adapter.name)
        findings.extend(adapter.run(url))
    return deduplicate(findings)


def evaluate_target(target: Dict, sources: List[str], intrusive: bool = False) -> Dict:
    from benchmark.matching import any_finding_matches, is_applicable

    name, url = target["name"], target["url"]
    expected = target.get("expected", [])

    logger.info("Scanning %s (%s)...", name, url)
    start = time.time()
    findings = scan_target(url, intrusive=intrusive)
    duration = round(time.time() - start, 1)

    applicable = [e for e in expected if is_applicable(e.get("detectable_by", []), sources)]
    matched = [e for e in applicable if any_finding_matches(findings, e["match"])]

    result = {
        "target": name,
        "url": url,
        "duration_s": duration,
        "total_findings": len(findings),
        "total_expected": len(expected),
        "applicable_expected": len(applicable),
        "matched": len(matched),
        "matched_keys": [e["key"] for e in matched],
        "missed_keys": [e["key"] for e in applicable if e not in matched],
    }

    if not expected:
        # Target bersih: temuan severity >= Medium dihitung false positive (kriteria plan).
        # Info/Low dari tool (deteksi teknologi dll.) dicatat terpisah sebagai noise.
        fps = [f for f in findings if severity_rank(f.severity) >= severity_rank(SEVERITY_MEDIUM)]
        noise = [f for f in findings if severity_rank(f.severity) < severity_rank(SEVERITY_MEDIUM)]
        result["false_positives"] = len(fps)
        result["false_positive_titles"] = [f.vulnerability for f in fps]
        result["low_info_noise"] = len(noise)
    else:
        result["recall"] = round(len(matched) / len(applicable), 2) if applicable else None

    return result


def run(ground_truth_path: str, save_baseline: bool, intrusive: bool = False) -> Dict:
    with open(ground_truth_path, "r", encoding="utf-8") as f:
        gt = yaml.safe_load(f)

    sources = available_sources(intrusive=intrusive)
    logger.info("Sumber deteksi tersedia: %s", sources)

    results = [evaluate_target(t, sources, intrusive=intrusive) for t in gt.get("targets", [])]
    report = {
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "sources": sources,
        "results": results,
    }

    os.makedirs(RESULTS_DIR, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = os.path.join(RESULTS_DIR, f"benchmark_{stamp}.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    logger.info("Hasil disimpan: %s", out)

    if save_baseline:
        baseline = os.path.join(RESULTS_DIR, "baseline.json")
        with open(baseline, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        logger.info("Baseline disimpan: %s", baseline)

    _print_table(results)
    return report


def _print_table(results: List[Dict]) -> None:
    print("\n" + "=" * 86)
    print(f"{'Target':<14}{'Findings':>9}{'Matched/App':>13}{'Expected':>10}{'Recall':>9}{'FP':>5}{'Durasi(s)':>11}")
    print("-" * 86)
    for r in results:
        recall = r.get("recall")
        recall_str = f"{recall:.0%}" if isinstance(recall, (int, float)) else "-"
        fp = r.get("false_positives", "-")
        matched_app = f"{r['matched']}/{r['applicable_expected']}"
        print(f"{r['target']:<14}{r['total_findings']:>9}{matched_app:>13}"
              f"{r['total_expected']:>10}{recall_str:>9}{str(fp):>5}{r['duration_s']:>11}")
    print("-" * 86)
    print("Catatan: 'Matched/App' = tertangkap / yang dapat dideteksi sumber saat ini; "
          "'Expected' = total celah diketahui.\nRecall rendah terhadap 'Expected' wajar "
          "di baseline native — ditingkatkan oleh adapter Fase 2.")
    print("=" * 86 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Omni-Web-Auditor benchmark harness")
    parser.add_argument("--ground-truth", default=os.path.join(HERE, "ground_truth.yaml"))
    parser.add_argument("--baseline", action="store_true", help="Simpan juga sebagai baseline.json")
    parser.add_argument("--intrusive", action="store_true", help="Aktifkan adapter intrusif (staging)")
    args = parser.parse_args()
    run(args.ground_truth, args.baseline, intrusive=args.intrusive)


if __name__ == "__main__":
    main()
