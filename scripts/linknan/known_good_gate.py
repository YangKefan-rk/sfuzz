#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


METHODS = ("sfuzz", "rfuzz", "directfuzz", "surgefuzz")
OUTPUT_FIELDS = [
    "testcase_id",
    "source",
    "category",
    "sfuzz_seed_path",
    "input_path",
    "input_format",
    "file_size",
    "status",
    "best_wall_time_sec",
    "worst_wall_time_sec",
    "methods_seen",
    "methods_passed",
    "timeout_methods",
    "invalid_methods",
    "multicore_methods_failed",
    "notes",
]


@dataclass(frozen=True)
class SelectedCase:
    testcase_id: str
    source: str
    category: str
    sfuzz_seed_path: str
    input_path: str
    input_format: str
    file_size: str


def bool_text(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes"}


def numeric(value: Any) -> float | None:
    if value in {None, ""}:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open(newline="", encoding="utf-8") as input_file:
        return list(csv.DictReader(input_file))


def load_selected_cases(root: Path) -> list[SelectedCase]:
    path = root / "manifests" / "selected_testcases.csv"
    if not path.is_file():
        raise FileNotFoundError(f"missing selected testcase manifest: {path}")
    cases: list[SelectedCase] = []
    with path.open(newline="", encoding="utf-8") as input_file:
        for row in csv.DictReader(input_file):
            cases.append(
                SelectedCase(
                    testcase_id=row.get("testcase_id", ""),
                    source=row.get("source", ""),
                    category=row.get("category", ""),
                    sfuzz_seed_path=row.get("sfuzz_seed") or row.get("sfuzz_seed_path", ""),
                    input_path=row.get("workload") or row.get("input_path", ""),
                    input_format=row.get("input_format", ""),
                    file_size=row.get("file_size", ""),
                )
            )
    return cases


def worker_rows(root: Path, method: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for csv_path in sorted((root / "results" / method / "workers").glob("worker-*/results.csv")):
        worker_id = csv_path.parent.name.replace("worker-", "")
        for row in read_csv(csv_path):
            item = dict(row)
            item.setdefault("worker_id", worker_id)
            rows.append(item)
    merged = root / "results" / method / "results.csv"
    if not rows and merged.is_file():
        rows = read_csv(merged)
    return rows


def worker_seed_case(root: Path, method: str, worker_id: str, index: int, cases: list[SelectedCase]) -> SelectedCase | None:
    list_kind = "sfuzz_seed_list" if method == "sfuzz" else "workload_seed_list"
    seed_list = root / "inputs" / "seed_lists" / f"{list_kind}.worker-{int(worker_id):03d}.txt"
    if not seed_list.is_file():
        return None
    entries = [line.split("#", 1)[0].strip() for line in seed_list.read_text(encoding="utf-8").splitlines()]
    entries = [entry for entry in entries if entry]
    if index < 0 or index >= len(entries):
        return None
    selected = entries[index]
    for case in cases:
        if selected in {case.input_path, case.sfuzz_seed_path}:
            return case
    selected_name = Path(selected).name
    selected_stem = Path(selected).stem
    for case in cases:
        if selected_name in {Path(case.input_path).name, Path(case.sfuzz_seed_path).name}:
            return case
        if selected_stem in {Path(case.input_path).stem, Path(case.sfuzz_seed_path).stem}:
            return case
    return None


def map_initial_row_by_worker_order(root: Path, row: dict[str, str], method: str, cases: list[SelectedCase]) -> SelectedCase | None:
    worker_id = str(row.get("worker_id", "") or "")
    if not worker_id.isdigit():
        return None
    if method == "sfuzz":
        raw_exec = str(row.get("campaign_exec", "") or "")
        if not raw_exec.isdigit() or row.get("mutation_index"):
            return None
        return worker_seed_case(root, method, worker_id, int(raw_exec) - 1, cases)
    if method == "rfuzz":
        if str(row.get("mutation", "")).strip().lower() != "initial-workload":
            return None
        raw_round = str(row.get("round", "") or "")
        if not raw_round.isdigit():
            return None
        return worker_seed_case(root, method, worker_id, int(raw_round) - 1, cases)
    if method == "directfuzz":
        if str(row.get("mutation", "")).strip().lower() != "initial-workload":
            return None
        raw_exec = str(row.get("campaign_exec", "") or "")
        if not raw_exec.isdigit():
            return None
        return worker_seed_case(root, method, worker_id, int(raw_exec), cases)
    if method == "surgefuzz":
        if str(row.get("round", "")).strip().lower() != "bootstrap":
            return None
        raw_seed_id = str(row.get("seed_id", "") or "")
        if raw_seed_id.isdigit():
            return worker_seed_case(root, method, worker_id, int(raw_seed_id), cases)
    return None


def index_by_basename(cases: list[SelectedCase]) -> dict[str, SelectedCase]:
    indexed: dict[str, SelectedCase] = {}
    for case in cases:
        keys = {
            case.testcase_id,
            Path(case.input_path).name,
            Path(case.input_path).stem,
            Path(case.sfuzz_seed_path).name,
            Path(case.sfuzz_seed_path).stem,
        }
        for key in keys:
            if key:
                indexed[key] = case
    return indexed


def row_case_keys(row: dict[str, str], method: str) -> set[str]:
    keys: set[str] = set()
    for field in (
        "seed",
        "seed_name",
        "seed_path",
        "input_path",
        "parent_seed",
        "case_name",
        "log_path",
        "case_dir",
    ):
        raw = str(row.get(field, "") or "")
        if not raw:
            continue
        path = Path(raw)
        keys.add(raw)
        keys.add(path.name)
        keys.add(path.stem)
    if method == "rfuzz":
        parent = str(row.get("parent_seed", "") or "")
        if parent:
            keys.add(parent)
    return {key for key in keys if key}


def map_row_to_case(
    root: Path,
    row: dict[str, str],
    method: str,
    cases: list[SelectedCase],
    by_key: dict[str, SelectedCase],
) -> SelectedCase | None:
    initial_case = map_initial_row_by_worker_order(root, row, method, cases)
    if initial_case is not None:
        return initial_case
    direct_fields = ["seed_path", "input_path", "seed"]
    for field in direct_fields:
        raw = str(row.get(field, "") or "")
        if not raw:
            continue
        for case in cases:
            if raw in {case.input_path, case.sfuzz_seed_path}:
                return case
    keys = row_case_keys(row, method)
    for key in keys:
        if key in by_key:
            return by_key[key]
    case_name = str(row.get("case_name", "") or "")
    if case_name:
        for case in cases:
            if Path(case.input_path).stem in case_name or Path(case.sfuzz_seed_path).stem in case_name or case.testcase_id in case_name:
                return case
    return None


def row_passed(row: dict[str, str]) -> bool:
    if bool_text(row.get("timed_out")) or bool_text(row.get("wall_timeout")):
        return False
    if bool_text(row.get("invalid_input")) or bool_text(row.get("infrastructure_error")):
        return False
    if str(row.get("run_outcome", "")).strip() in {"good_trap", "tohost_exit"}:
        return True
    exit_code = numeric(row.get("exit_code"))
    if exit_code == 0:
        return True
    return bool_text(row.get("good_trap_seen")) or bool_text(row.get("tohost_exit_seen"))


def row_requires_core1(row: dict[str, str]) -> bool:
    return bool_text(row.get("requires_core1_handoff")) or bool_text(row.get("sfuzz_core1_staged"))


def row_core1_failed(row: dict[str, str]) -> bool:
    if not row_requires_core1(row):
        return False
    return not (bool_text(row.get("core1_executed")) and bool_text(row.get("formal_multicore_result")))


def row_is_initial_replay(method: str, row: dict[str, str]) -> bool:
    if method == "sfuzz":
        return not str(row.get("mutation_index", "") or "").strip()
    if method == "rfuzz":
        return str(row.get("mutation", "") or "").strip().lower() == "initial-workload"
    if method == "directfuzz":
        return str(row.get("mutation", "") or "").strip().lower() == "initial-workload"
    if method == "surgefuzz":
        return str(row.get("round", "") or "").strip().lower() == "bootstrap"
    return False


def mutation_diagnostic_rows(rows: list[tuple[str, dict[str, str]]]) -> list[dict[str, Any]]:
    by_method: dict[str, list[dict[str, str]]] = defaultdict(list)
    for method, row in rows:
        by_method[method].append(row)
    output: list[dict[str, Any]] = []
    for method, method_rows in sorted(by_method.items()):
        walls = [numeric(row.get("wall_time_sec")) for row in method_rows]
        walls = [value for value in walls if value is not None]
        output.append(
            {
                "method": method,
                "mutation_rows": len(method_rows),
                "mutation_timeouts": sum(
                    1 for row in method_rows if bool_text(row.get("timed_out")) or bool_text(row.get("wall_timeout"))
                ),
                "mutation_invalid_inputs": sum(
                    1 for row in method_rows if bool_text(row.get("invalid_input")) or bool_text(row.get("infrastructure_error"))
                ),
                "max_wall_time_sec": round(max(walls), 6) if walls else "",
            }
        )
    return output


def classify_case(
    case: SelectedCase,
    rows_by_case: dict[str, list[tuple[str, dict[str, str]]]],
    min_wall: float,
    timeout_sec: float,
) -> dict[str, Any]:
    records = rows_by_case.get(case.testcase_id, [])
    methods_seen = sorted({method for method, _row in records})
    passed_methods = sorted({method for method, row in records if row_passed(row)})
    timeout_methods = sorted({method for method, row in records if bool_text(row.get("timed_out")) or bool_text(row.get("wall_timeout"))})
    invalid_methods = sorted({method for method, row in records if bool_text(row.get("invalid_input")) or bool_text(row.get("infrastructure_error"))})
    multicore_failed = sorted({method for method, row in records if row_core1_failed(row)})
    walls = [numeric(row.get("wall_time_sec")) for _method, row in records]
    walls = [value for value in walls if value is not None]
    passed_walls = [numeric(row.get("wall_time_sec")) for _method, row in records if row_passed(row)]
    passed_walls = [value for value in passed_walls if value is not None]
    notes: list[str] = []
    if not records:
        status = "not_observed"
        notes.append("no row mapped to testcase")
    elif timeout_methods:
        status = "timeout_quarantine"
    elif invalid_methods:
        status = "invalid_quarantine"
    elif multicore_failed:
        status = "multicore_quarantine"
    elif len(passed_methods) < len(METHODS):
        status = "partial_pass"
        missing = sorted(set(METHODS) - set(passed_methods))
        notes.append("missing_pass=" + ",".join(missing))
    elif passed_walls and min(passed_walls) < min_wall:
        status = "short_diagnostic"
    elif passed_walls and max(passed_walls) <= timeout_sec:
        status = "known_good"
    else:
        status = "timeout_quarantine"
    if records:
        notes.append(f"records={len(records)}")
    return {
        "testcase_id": case.testcase_id,
        "source": case.source,
        "category": case.category,
        "sfuzz_seed_path": case.sfuzz_seed_path,
        "input_path": case.input_path,
        "input_format": case.input_format,
        "file_size": case.file_size,
        "status": status,
        "best_wall_time_sec": round(min(walls), 6) if walls else "",
        "worst_wall_time_sec": round(max(walls), 6) if walls else "",
        "methods_seen": ";".join(methods_seen),
        "methods_passed": ";".join(passed_methods),
        "timeout_methods": ";".join(timeout_methods),
        "invalid_methods": ";".join(invalid_methods),
        "multicore_methods_failed": ";".join(multicore_failed),
        "notes": ";".join(notes),
    }


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_report(root: Path, rows: list[dict[str, Any]], output: Path, min_wall: float, timeout_sec: float) -> None:
    status_counts = Counter(str(row["status"]) for row in rows)
    category_counts: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        category_counts[str(row["status"])][str(row["category"])] += 1
    lines = [
        "# Known-good Workload Gate",
        "",
        f"campaign: `{root}`",
        f"target wall time: `{int(min_wall)}-{int(timeout_sec)}s`",
        "",
        "## Summary",
        "",
        "| status | count |",
        "|---|---:|",
    ]
    for status, count in status_counts.most_common():
        lines.append(f"| {status} | {count} |")
    lines.extend(["", "## Status By Category", ""])
    for status, counter in sorted(category_counts.items()):
        compact = ", ".join(f"{category}: {count}" for category, count in counter.most_common())
        lines.append(f"- {status}: {compact}")
    lines.extend(["", "## Candidate Rows", ""])
    lines.append("| testcase | category | status | worst wall(s) | passed methods | quarantine |")
    lines.append("|---|---|---|---:|---|---|")
    for row in rows:
        quarantine = row["timeout_methods"] or row["invalid_methods"] or row["multicore_methods_failed"]
        lines.append(
            f"| {row['testcase_id']} | {row['category']} | {row['status']} | {row['worst_wall_time_sec']} | "
            f"{row['methods_passed']} | {quarantine} |"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate known-good and quarantine manifests from a T2 gate run")
    parser.add_argument("--campaign-root", type=Path, required=True)
    parser.add_argument("--min-wall-time-sec", type=float, default=300.0)
    parser.add_argument("--timeout-sec", type=float, default=900.0)
    parser.add_argument(
        "--include-mutations",
        action="store_true",
        help="include mutation rows in testcase classification; default uses only initial/bootstrap replay rows",
    )
    args = parser.parse_args()

    root = args.campaign_root.expanduser().resolve()
    cases = load_selected_cases(root)
    by_key = index_by_basename(cases)
    rows_by_case: dict[str, list[tuple[str, dict[str, str]]]] = defaultdict(list)
    unmapped: list[dict[str, str]] = []
    mutation_records: list[tuple[str, dict[str, str]]] = []
    for method in METHODS:
        for row in worker_rows(root, method):
            if not row_is_initial_replay(method, row):
                mutation_records.append((method, row))
                if not args.include_mutations:
                    continue
            case = map_row_to_case(root, row, method, cases, by_key)
            if case is None:
                row = dict(row)
                row["method"] = method
                unmapped.append(row)
                continue
            rows_by_case[case.testcase_id].append((method, row))

    gate_rows = [classify_case(case, rows_by_case, args.min_wall_time_sec, args.timeout_sec) for case in cases]
    known_good = [row for row in gate_rows if row["status"] == "known_good"]
    quarantine = [row for row in gate_rows if str(row["status"]).endswith("_quarantine")]
    diagnostics = [row for row in gate_rows if row not in known_good and row not in quarantine]

    manifests = root / "manifests"
    reports = root / "reports"
    write_csv(manifests / "known_good_gate_status.csv", gate_rows, OUTPUT_FIELDS)
    write_csv(manifests / "known_good_manifest.csv", known_good, OUTPUT_FIELDS)
    write_csv(manifests / "diagnostic_short_manifest.csv", diagnostics, OUTPUT_FIELDS)
    write_csv(manifests / "timeout_quarantine_manifest.csv", quarantine, OUTPUT_FIELDS)
    (manifests / "timeout_quarantine.txt").write_text(
        "\n".join(str(row["testcase_id"]) for row in quarantine) + ("\n" if quarantine else ""),
        encoding="utf-8",
    )
    if unmapped:
        write_csv(
            manifests / "known_good_unmapped_rows.csv",
            unmapped,
            sorted({key for row in unmapped for key in row.keys()}),
        )
    mutation_diagnostics = mutation_diagnostic_rows(mutation_records)
    if mutation_diagnostics:
        write_csv(
            manifests / "mutation_timeout_diagnostics.csv",
            mutation_diagnostics,
            ["method", "mutation_rows", "mutation_timeouts", "mutation_invalid_inputs", "max_wall_time_sec"],
        )
    write_report(root, gate_rows, reports / "known_good_gate.md", args.min_wall_time_sec, args.timeout_sec)
    (reports / "known_good_gate.json").write_text(
        json.dumps(
            {
                "campaign_root": str(root),
                "known_good": len(known_good),
                "quarantine": len(quarantine),
                "diagnostic": len(diagnostics),
                "unmapped_rows": len(unmapped),
                "mutation_diagnostics": mutation_diagnostics,
                "classification_scope": "all rows including mutations" if args.include_mutations else "initial/bootstrap replay rows",
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    print(f"known-good manifest: {manifests / 'known_good_manifest.csv'}")
    print(f"timeout quarantine: {manifests / 'timeout_quarantine.txt'}")
    print(f"gate report: {reports / 'known_good_gate.md'}")
    print(f"known_good={len(known_good)} quarantine={len(quarantine)} diagnostic={len(diagnostics)} unmapped_rows={len(unmapped)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
