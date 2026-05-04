#!/usr/bin/env python3
import argparse
import json
import sys
import time
from pathlib import Path

import yaml

REQUIRED_SECTIONS = [".text", ".rdata"]
REQUIRED_METADATA_KEYS = ["build_id", "opcode_map_version", "integrity_marker"]


def load_json(path: Path, default):
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return default


def save_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def static_validate(binary_dir: Path):
    report = {"pass": True, "errors": []}
    sections = load_json(binary_dir / "sections.json", [])
    metadata = load_json(binary_dir / "metadata.json", {})
    opcode_map = load_json(binary_dir / "opcode_map.json", {})
    integrity = load_json(binary_dir / "integrity_markers.json", {})

    for section in REQUIRED_SECTIONS:
        if section not in sections:
            report["pass"] = False
            report["errors"].append(f"missing required section: {section}")

    for key in REQUIRED_METADATA_KEYS:
        if key not in metadata:
            report["pass"] = False
            report["errors"].append(f"missing required metadata key: {key}")

    if not opcode_map:
        report["pass"] = False
        report["errors"].append("opcode map is empty")

    if not integrity.get("markers"):
        report["pass"] = False
        report["errors"].append("integrity markers missing")

    return report


def run_scenario_matrix(matrix_path: Path, scenario_results: dict):
    matrix = yaml.safe_load(matrix_path.read_text(encoding="utf-8"))
    failures = []
    total_assertions = 0

    for scenario in matrix.get("scenarios", []):
        sid = scenario["id"]
        actual = scenario_results.get(sid, {})
        for key, expected in scenario.get("expected", {}).items():
            total_assertions += 1
            if actual.get(key) is not expected:
                failures.append(
                    {
                        "scenario": sid,
                        "assertion": key,
                        "expected": expected,
                        "actual": actual.get(key),
                    }
                )

    return {
        "pass": len(failures) == 0,
        "total_assertions": total_assertions,
        "failed_assertions": failures,
    }


def compute_metrics(detections: dict, performance: dict, budget_ms: int):
    tp = detections.get("tp", 0)
    tn = detections.get("tn", 0)
    fp = detections.get("fp", 0)
    fn = detections.get("fn", 0)
    total = max(tp + tn + fp + fn, 1)

    overhead_ms = performance.get("protected_runtime_ms", 0) - performance.get("baseline_runtime_ms", 0)
    return {
        "false_positive_rate": fp / total,
        "false_negative_rate": fn / total,
        "accuracy": (tp + tn) / total,
        "overhead_ms": overhead_ms,
        "budget_ms": budget_ms,
        "budget_pass": overhead_ms <= budget_ms,
    }


def write_trend_report(history_path: Path, commit: str, qa_report: dict):
    history = load_json(history_path, [])
    history.append(
        {
            "commit": commit,
            "timestamp_utc": int(time.time()),
            "static_pass": qa_report["static_validation"]["pass"],
            "matrix_pass": qa_report["scenario_matrix"]["pass"],
            "fp_rate": qa_report["metrics"]["false_positive_rate"],
            "fn_rate": qa_report["metrics"]["false_negative_rate"],
            "overhead_ms": qa_report["metrics"]["overhead_ms"],
        }
    )
    save_json(history_path, history)


def main():
    parser = argparse.ArgumentParser(description="IronLock QA framework runner")
    parser.add_argument("--binary-dir", default="tests/fixtures/protected_bin")
    parser.add_argument("--matrix", default="tests/qa/scenario_matrix.yaml")
    parser.add_argument("--results", default="tests/fixtures/scenario_results.json")
    parser.add_argument("--detections", default="tests/fixtures/detections.json")
    parser.add_argument("--performance", default="tests/fixtures/performance.json")
    parser.add_argument("--budget-ms", type=int, default=75)
    parser.add_argument("--artifacts-dir", default="artifacts/qa")
    parser.add_argument("--commit", default="local")
    args = parser.parse_args()

    artifacts_dir = Path(args.artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    qa_report = {
        "static_validation": static_validate(Path(args.binary_dir)),
        "scenario_matrix": run_scenario_matrix(Path(args.matrix), load_json(Path(args.results), {})),
        "metrics": compute_metrics(load_json(Path(args.detections), {}), load_json(Path(args.performance), {}), args.budget_ms),
    }

    save_json(artifacts_dir / "qa_report.json", qa_report)
    write_trend_report(artifacts_dir / "qa_trends.json", args.commit, qa_report)

    summary = {
        "pass": all(
            [
                qa_report["static_validation"]["pass"],
                qa_report["scenario_matrix"]["pass"],
                qa_report["metrics"]["budget_pass"],
            ]
        )
    }
    save_json(artifacts_dir / "qa_summary.json", summary)

    print(json.dumps(qa_report, indent=2))
    return 0 if summary["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
