#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

METHODS = ("sfuzz", "rfuzz", "directfuzz", "surgefuzz")
CYCLE_RE = re.compile(r"--cycles=|\+max-cycles=5000|EXCEEDED MAX CYCLE")


@dataclass
class MethodAudit:
    method: str
    rows: int = 0
    worker_csvs: int = 0
    mutation_rows: int = 0
    mutation_ratio: float = 0.0
    paper_faithful_rows: int = 0
    timed_out_rows: int = 0
    design_bug_rows: int = 0
    invalid_input_rows: int = 0
    cycle_violations: int = 0
    missing_case_dir: int = 0
    missing_command_log: int = 0
    issues: list[str] = field(default_factory=list)
    counters: dict[str, Counter[str]] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.issues


def bool_text(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes"}


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as input_file:
        return list(csv.DictReader(input_file))


def load_worker_rows(root: Path, method: str) -> tuple[list[Path], list[dict[str, str]]]:
    csvs = sorted((root / "results" / method / "workers").glob("worker-*/results.csv"))
    rows: list[dict[str, str]] = []
    for csv_path in csvs:
        worker_id = csv_path.parent.name.replace("worker-", "")
        for row in read_rows(csv_path):
            row = dict(row)
            row.setdefault("worker_id", worker_id)
            rows.append(row)
    merged = root / "results" / method / "results.csv"
    if not csvs and merged.is_file():
        rows = read_rows(merged)
    return csvs, rows


def is_mutation_row(row: dict[str, str]) -> bool:
    fuzzer = str(row.get("fuzzer", "")).strip().lower()
    if fuzzer == "sfuzz":
        return nonempty(row, "mutation_index") or nonempty(row, "semantic_operator")
    if fuzzer == "rfuzz":
        mutation = str(row.get("mutation", "")).strip().lower()
        return bool(mutation) and mutation != "initial-workload"
    if fuzzer == "directfuzz":
        mutation = str(row.get("mutation", "")).strip().lower()
        index = str(row.get("mutation_index", "")).strip()
        return bool(index) or (bool(mutation) and mutation not in {"initial", "initial-workload"})
    if fuzzer == "surgefuzz":
        round_name = str(row.get("round", "")).strip().lower()
        mutation_kind = str(row.get("mutation_kind", "")).strip().lower()
        return round_name not in {"", "bootstrap"} and "initial" not in mutation_kind
    markers = [row.get("mutation_index", ""), row.get("mutation", ""), row.get("mutation_kind", "")]
    text = ";".join(str(item) for item in markers if str(item).strip()).lower()
    return bool(text) and not any(token in text for token in ("initial", "bootstrap", "initial-workload"))


def command_log_has_cycle_violation(row: dict[str, str]) -> bool:
    if bool_text(row.get("command_has_cycles_arg")) or bool_text(row.get("command_has_max_cycles_plusarg")):
        return True
    path_text = row.get("command_log_path") or ""
    if not path_text:
        return False
    path = Path(path_text)
    if not path.is_file():
        return False
    try:
        return bool(CYCLE_RE.search(path.read_text(encoding="utf-8", errors="replace")))
    except OSError:
        return False


def counter(rows: list[dict[str, str]], key: str) -> Counter[str]:
    return Counter(str(row.get(key, "")) for row in rows)


def nonempty(row: dict[str, str], key: str) -> bool:
    return str(row.get(key, "")).strip() != ""


def surgefuzz_trace_summary_from_csv(row: dict[str, str]) -> tuple[int, int] | None:
    trace_path = str(row.get("trace_path", "")).strip()
    if not trace_path:
        return None
    path = Path(trace_path)
    if not path.is_file():
        return None
    try:
        with path.open(newline="", encoding="utf-8") as input_file:
            reader = csv.DictReader(input_file)
            if reader.fieldnames is None or "coverage_target" not in reader.fieldnames:
                return None
            rows = 0
            target_hits = 0
            for trace_row in reader:
                rows += 1
                raw_value = str(trace_row.get("coverage_target", "") or "0")
                try:
                    if int(raw_value, 0) != 0:
                        target_hits += 1
                except ValueError:
                    return None
    except OSError:
        return None
    return rows, target_hits


def surgefuzz_trace_summary_available(row: dict[str, str]) -> bool:
    if nonempty(row, "trace_rows") and nonempty(row, "trace_call_count") and nonempty(row, "trace_target_hit_count"):
        return True
    recovered = surgefuzz_trace_summary_from_csv(row)
    if recovered is None:
        return False
    rows, _target_hits = recovered
    raw_trace_rows = str(row.get("trace_rows", "")).strip()
    if raw_trace_rows:
        try:
            return int(raw_trace_rows, 0) == rows
        except ValueError:
            return False
    return rows > 0


def add_common_checks(
    audit: MethodAudit,
    rows: list[dict[str, str]],
    expected_rows: int,
    complete: bool,
    *,
    require_paper_faithful: bool = True,
) -> None:
    if complete and audit.rows != expected_rows:
        audit.issues.append(f"rows {audit.rows} != expected {expected_rows}")
    elif not complete and audit.rows == 0:
        audit.issues.append("no rows yet")

    if audit.rows:
        if audit.cycle_violations:
            audit.issues.append(f"cycle-limit command/log violations: {audit.cycle_violations}")
        if audit.missing_case_dir:
            audit.issues.append(f"rows with missing case_dir: {audit.missing_case_dir}")
        if audit.missing_command_log:
            audit.issues.append(f"rows with missing command_log_path: {audit.missing_command_log}")
        if require_paper_faithful and audit.paper_faithful_rows != audit.rows:
            audit.issues.append(f"paper_faithful rows {audit.paper_faithful_rows} != rows {audit.rows}")
        abi = counter(rows, "required_native_abi")
        if any(key for key in abi if key.strip()):
            audit.issues.append(f"required_native_abi is non-empty: {dict(abi)}")


def audit_method(root: Path, method: str, expected_rows: int, complete: bool) -> MethodAudit:
    csvs, rows = load_worker_rows(root, method)
    audit = MethodAudit(method=method, rows=len(rows), worker_csvs=len(csvs))
    audit.mutation_rows = sum(1 for row in rows if is_mutation_row(row))
    audit.mutation_ratio = round(audit.mutation_rows / audit.rows, 6) if audit.rows else 0.0
    audit.paper_faithful_rows = sum(1 for row in rows if bool_text(row.get("paper_faithful")))
    audit.timed_out_rows = sum(1 for row in rows if bool_text(row.get("timed_out")))
    audit.design_bug_rows = sum(
        1
        for row in rows
        if not bool_text(row.get("invalid_input")) and (bool_text(row.get("design_bug")) or bool_text(row.get("bug_triggered")))
    )
    audit.invalid_input_rows = sum(1 for row in rows if bool_text(row.get("invalid_input")))
    audit.cycle_violations = sum(1 for row in rows if command_log_has_cycle_violation(row))
    audit.missing_case_dir = sum(1 for row in rows if nonempty(row, "case_dir") and not Path(row["case_dir"]).is_dir())
    audit.missing_command_log = sum(
        1 for row in rows if nonempty(row, "command_log_path") and not Path(row["command_log_path"]).is_file()
    )
    for key in (
        "timed_out",
        "design_bug",
        "invalid_input",
        "paper_faithful",
        "required_native_abi",
        "coverage_backend",
        "common_coverage_name",
    ):
        if rows and key in rows[0]:
            audit.counters[key] = counter(rows, key)

    surge_workload_mode = method == "surgefuzz" and any(str(row.get("input_format", "")).startswith("linknan-workload") for row in rows)
    add_common_checks(audit, rows, expected_rows, complete, require_paper_faithful=not surge_workload_mode)
    if complete and audit.rows and audit.mutation_ratio < 0.8:
        audit.issues.append(f"mutation ratio {audit.mutation_ratio:.3f} < 0.8")

    if method == "sfuzz" and rows:
        operators = counter(rows, "semantic_operator")
        nonempty_ops = [op for op in operators if op.strip()]
        audit.counters["semantic_operator"] = operators
        if not nonempty_ops:
            audit.issues.append("SFuzz semantic_operator never appears")
        parent_ids = {row.get("parent_corpus_id", "") for row in rows if row.get("parent_corpus_id", "") != ""}
        if complete and len(parent_ids) <= 1:
            audit.issues.append("SFuzz parent selection appears fixed to one corpus entry")
        bad_core1 = [
            row
            for row in rows
            if bool_text(row.get("requires_core1_handoff"))
            and (not bool_text(row.get("core1_executed")) or not bool_text(row.get("formal_multicore_result")))
        ]
        if bad_core1:
            audit.issues.append(f"SFuzz core1-required rows not formal: {len(bad_core1)}")
        if counter(rows, "coverage_backend") != Counter({"sfuzz_native": len(rows)}):
            audit.issues.append(f"SFuzz coverage backend mismatch: {dict(counter(rows, 'coverage_backend'))}")

    if method == "rfuzz" and rows:
        if any(bool_text(row.get("invalid_input")) and bool_text(row.get("design_bug")) for row in rows):
            audit.issues.append("RFuzz invalid_input rows are still counted as design_bug")
        if any(row.get("toggle_bitmap_source") != "vcs-native-abi" for row in rows):
            audit.issues.append(f"RFuzz toggle source mismatch: {dict(counter(rows, 'toggle_bitmap_source'))}")
        if any(not nonempty(row, "rfuzz_mux_total") or str(row.get("rfuzz_mux_total")) == "0" for row in rows):
            audit.issues.append("RFuzz has rows without mux total")

    if method == "directfuzz" and rows:
        if any(row.get("coverage_backend") in {"dev-mock", "stub"} for row in rows):
            audit.issues.append("DirectFuzz dev-mock/stub coverage leaked into formal run")
        expected_backend = "directfuzz_per_instance_mux_toggle_file"
        if any(row.get("coverage_backend") != expected_backend for row in rows):
            audit.issues.append(f"DirectFuzz backend mismatch: {dict(counter(rows, 'coverage_backend'))}")
        if any(row.get("native_coverage_source") != "vcs-native-abi" for row in rows):
            audit.issues.append(f"DirectFuzz native source mismatch: {dict(counter(rows, 'native_coverage_source'))}")
        if any(not nonempty(row, "distance") for row in rows):
            audit.issues.append("DirectFuzz has rows without distance")
        if any(not nonempty(row, "target_instance") for row in rows):
            audit.issues.append("DirectFuzz has rows without target_instance")

    if method == "surgefuzz" and rows:
        workload_mode = any(str(row.get("input_format", "")).startswith("linknan-workload") for row in rows)
        if any(row.get("trace_source") != "vcs-native-abi" for row in rows):
            audit.issues.append(f"SurgeFuzz trace_source mismatch: {dict(counter(rows, 'trace_source'))}")
        if any(row.get("coverage_backend") != "surgefuzz_vcs_native_abi_trace" for row in rows):
            audit.issues.append(f"SurgeFuzz coverage backend mismatch: {dict(counter(rows, 'coverage_backend'))}")
        missing_trace_summary = [
            row
            for row in rows
            if not (
                nonempty(row, "trace_rows")
                and nonempty(row, "trace_call_count")
                and nonempty(row, "trace_target_hit_count")
            )
        ]
        unrecoverable = [row for row in missing_trace_summary if not surgefuzz_trace_summary_available(row)]
        if unrecoverable:
            audit.issues.append(f"SurgeFuzz has rows without recoverable trace summary: {len(unrecoverable)}")
        if missing_trace_summary and not unrecoverable:
            audit.counters["trace_summary_fallback"] = Counter({"csv_samples": len(missing_trace_summary)})
        if workload_mode and audit.paper_faithful_rows:
            audit.issues.append("SurgeFuzz workload-mode rows must not be marked artifact paper_faithful")

    return audit


def write_report(root: Path, audits: list[MethodAudit], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# T2 Campaign Correctness Audit", "", f"campaign: `{root}`", ""]
    lines.extend(
        [
            "| method | rows | worker CSVs | mutation ratio | timeouts | design bugs | invalid inputs | cycle violations | status |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---|",
        ]
    )
    for audit in audits:
        status = "PASS" if audit.ok else "CHECK"
        lines.append(
            f"| {audit.method} | {audit.rows} | {audit.worker_csvs} | {audit.mutation_ratio:.3f} | "
            f"{audit.timed_out_rows} | {audit.design_bug_rows} | {audit.invalid_input_rows} | "
            f"{audit.cycle_violations} | {status} |"
        )
    lines.append("")
    for audit in audits:
        lines.append(f"## {audit.method}")
        if audit.issues:
            for issue in audit.issues:
                lines.append(f"- {issue}")
        else:
            lines.append("- no correctness issues detected by this audit")
        for key, values in audit.counters.items():
            compact = ", ".join(f"{k or '<empty>'}: {v}" for k, v in values.most_common(8))
            lines.append(f"- {key}: {compact}")
        lines.append("")
    output.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit a T2 four-fuzzer campaign for result correctness")
    parser.add_argument("--campaign-root", type=Path, required=True)
    parser.add_argument("--expected-rows", type=int, default=1000)
    parser.add_argument("--complete", action="store_true", help="require every method to have exactly --expected-rows rows")
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--json-output", type=Path, default=None)
    args = parser.parse_args()

    root = args.campaign_root.expanduser().resolve()
    audits = [audit_method(root, method, args.expected_rows, args.complete) for method in METHODS]
    output = args.output or (root / "reports" / "correctness_audit.md")
    write_report(root, audits, output)
    json_output = args.json_output or output.with_suffix(".json")
    json_output.write_text(
        json.dumps([audit.__dict__ | {"counters": {k: dict(v) for k, v in audit.counters.items()}} for audit in audits], indent=2),
        encoding="utf-8",
    )
    print(f"audit report: {output}")
    for audit in audits:
        status = "PASS" if audit.ok else "CHECK"
        print(
            f"{audit.method}: {status} rows={audit.rows} mutation_ratio={audit.mutation_ratio:.3f} "
            f"timeouts={audit.timed_out_rows} bugs={audit.design_bug_rows} invalid={audit.invalid_input_rows}"
        )
        for issue in audit.issues:
            print(f"  - {issue}")
    return 1 if any(not audit.ok for audit in audits) else 0


if __name__ == "__main__":
    raise SystemExit(main())
