#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import shlex
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from linknan.common import require_file, write_table  # noqa: E402
from linknan.config import DEFAULT_CONFIG, SFUZZ_HOME  # noqa: E402


CAMPAIGN_FIELDS = [
    "method",
    "command",
    "env",
    "work_dir",
    "output_csv",
    "output_json",
    "coverage_name",
    "formal_guard",
]
SUMMARY_FIELDS = [
    "method",
    "result_csv",
    "rows",
    "mutation_rows",
    "mutation_ratio",
    "paper_faithful_rows",
    "timed_out_rows",
    "bug_rows",
    "no_cycle_limit_rows",
    "command_cycle_violations",
    "final_covered",
    "final_total",
    "final_percent",
    "auc_exec_percent",
    "notes",
]
DEFAULT_DIRECT_TARGET = "SimTop.soc.cc_0.tile.core.memBlock"


@dataclass(frozen=True)
class Testcase:
    testcase_id: str
    source: str
    category: str
    sfuzz_seed: Path
    workload: Path
    input_format: str
    file_size: int


@dataclass(frozen=True)
class CampaignPaths:
    root: Path
    inputs: Path
    results: Path
    logs: Path
    reports: Path
    manifests: Path
    scripts: Path

    @classmethod
    def create(cls, root: Path) -> "CampaignPaths":
        paths = cls(
            root=root,
            inputs=root / "inputs",
            results=root / "results",
            logs=root / "logs",
            reports=root / "reports",
            manifests=root / "manifests",
            scripts=root / "scripts",
        )
        for directory in [paths.inputs, paths.results, paths.logs, paths.reports, paths.manifests, paths.scripts]:
            directory.mkdir(parents=True, exist_ok=True)
        return paths


def now_slug() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def resolve_manifest_path(raw: str, manifest: Path) -> Path:
    path = Path(raw).expanduser()
    if path.is_absolute():
        return path
    return (SFUZZ_HOME / path).resolve()


def load_testcases(manifest: Path, limit: int) -> list[Testcase]:
    require_file(manifest)
    rows: list[Testcase] = []
    with manifest.open(newline="", encoding="utf-8") as input_file:
        reader = csv.DictReader(input_file)
        required = {"testcase_id", "source", "category", "sfuzz_seed_path", "input_path", "input_format", "file_size"}
        missing = sorted(required - set(reader.fieldnames or []))
        if missing:
            raise ValueError(f"{manifest}: missing required columns: {', '.join(missing)}")
        for row in reader:
            sfuzz_seed = resolve_manifest_path(row.get("sfuzz_seed_path", ""), manifest)
            workload_raw = row.get("rfuzz_workload_path") or row.get("input_path") or ""
            workload = resolve_manifest_path(workload_raw, manifest)
            if not sfuzz_seed.is_file() or not workload.is_file():
                continue
            rows.append(
                Testcase(
                    testcase_id=str(row["testcase_id"]),
                    source=str(row["source"]),
                    category=str(row["category"]),
                    sfuzz_seed=sfuzz_seed,
                    workload=workload,
                    input_format=str(row["input_format"]),
                    file_size=int(row.get("file_size") or workload.stat().st_size),
                )
            )
            if limit > 0 and len(rows) >= limit:
                break
    if not rows:
        raise ValueError(f"{manifest}: no runnable testcase with both SFUZ seed and workload image")
    return rows


def write_seed_lists(paths: CampaignPaths, testcases: list[Testcase]) -> tuple[Path, Path, Path]:
    seed_lists = paths.inputs / "seed_lists"
    seed_lists.mkdir(parents=True, exist_ok=True)
    sfuzz_list = seed_lists / "sfuzz_seed_list.txt"
    workload_list = seed_lists / "workload_seed_list.txt"
    sfuzz_list.write_text("\n".join(str(case.sfuzz_seed) for case in testcases) + "\n", encoding="utf-8")
    workload_list.write_text("\n".join(str(case.workload) for case in testcases) + "\n", encoding="utf-8")

    manifest_csv = paths.manifests / "selected_testcases.csv"
    with manifest_csv.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(
            output_file,
            fieldnames=["testcase_id", "source", "category", "sfuzz_seed", "workload", "input_format", "file_size"],
        )
        writer.writeheader()
        for case in testcases:
            writer.writerow(
                {
                    "testcase_id": case.testcase_id,
                    "source": case.source,
                    "category": case.category,
                    "sfuzz_seed": case.sfuzz_seed,
                    "workload": case.workload,
                    "input_format": case.input_format,
                    "file_size": case.file_size,
                }
            )
    return sfuzz_list, workload_list, manifest_csv


def command_to_text(command: list[str]) -> str:
    return " ".join(shlex.quote(item) for item in command)


def run_py() -> str:
    return sys.executable or "python3"


def build_common_args(args: argparse.Namespace, work_dir: Path, output_csv: Path, output_json: Path, coverage: str) -> list[str]:
    common = [
        "--config",
        str(args.config),
        "--linknan-root",
        str(args.linknan_root),
        "--work-dir",
        str(work_dir),
        "--no-cycle-limit",
        "--timeout-sec",
        str(args.timeout_sec),
        "--firrtl-cov",
        coverage,
        "--output-csv",
        str(output_csv),
        "--output-json",
        str(output_json),
    ]
    if args.build_mode == "auto":
        pass
    elif args.build_mode == "build":
        common.append("--build")
    elif args.build_mode == "rebuild":
        common.extend(["--build", "--rebuild-comp"])
    else:
        common.append("--skip-build")
    if args.build_chisel:
        common.append("--build-chisel")
    if args.build_timeout_sec > 0:
        common.extend(["--build-timeout-sec", str(args.build_timeout_sec)])
    if args.simv_args:
        common.extend(["--simv-args", args.simv_args])
    return common


def campaign_commands(args: argparse.Namespace, paths: CampaignPaths, sfuzz_list: Path, workload_list: Path) -> list[dict[str, Any]]:
    run_script = SFUZZ_HOME / "scripts" / "linknan" / "run.py"
    direct_metadata = args.direct_metadata.expanduser().resolve()
    surge_manifest = args.surge_target_manifest.expanduser().resolve()
    commands: list[dict[str, Any]] = []

    def add(method: str, coverage: str, formal_guard: str, tail: list[str], env: dict[str, str] | None = None) -> None:
        work_dir = paths.results / method / "work"
        output_csv = paths.results / method / "results.csv"
        output_json = paths.results / method / "results.json"
        command = [run_py(), str(run_script), method]
        command.extend(build_common_args(args, work_dir, output_csv, output_json, coverage))
        command.extend(tail)
        commands.append(
            {
                "method": method,
                "command": command,
                "env": env or {},
                "work_dir": work_dir,
                "output_csv": output_csv,
                "output_json": output_json,
                "coverage_name": coverage,
                "formal_guard": formal_guard,
            }
        )

    add(
        "sfuzz",
        "SFUZZ.native",
        "SFUZZ.native; semantic scheduler; short_run filtered by target_min_wall_time_sec",
        [
            "--seed-list",
            str(sfuzz_list),
            "--campaign-runs",
            str(args.exec_budget),
            "--rng-seed",
            str(args.rng_seed),
            "--scheduler-policy",
            args.sfuzz_scheduler,
            "--target-min-wall-time-sec",
            str(args.target_min_wall_time_sec),
            "--enable-core1-handoff",
        ],
        {"NUM_CORES": str(args.sfuzz_num_cores)},
    )
    add(
        "rfuzz",
        "RFuzz.mux-toggle",
        "--require-formal-feedback; LinkNan workload scope; VCS native mux-toggle",
        [
            "--seed-list",
            str(workload_list),
            "--rfuzz-rounds",
            str(args.exec_budget),
            "--rfuzz-random-seed",
            str(args.rng_seed),
            "--rfuzz-toggle-bitmap-source",
            "vcs-native-abi",
            "--require-formal-feedback",
        ],
    )
    add(
        "directfuzz",
        "DirectFuzz.mux-toggle",
        "--require-paper-native; static metadata; dynamic per-instance VCS feedback",
        [
            "--seed-list",
            str(workload_list),
            "--target-instance",
            args.direct_target_instance,
            "--metadata",
            str(direct_metadata),
            "--metadata-source",
            "static-analysis",
            "--coverage-backend",
            "native-file",
            "--native-coverage-source",
            "vcs-native-abi",
            "--max-execs",
            str(args.exec_budget),
            "--mutations",
            str(args.exec_budget),
            "--rng-seed",
            str(args.rng_seed),
            "--require-paper-native",
        ],
    )
    add(
        "surgefuzz",
        "SurgeFuzz.trace",
        "--require-paper-native; single target; artifact Program mutation; no rotation",
        [
            "--input-mode",
            "artifact-program",
            "--max-execs",
            str(args.exec_budget),
            "--mutations",
            str(args.exec_budget),
            "--initial-seed-count",
            str(args.surge_initial_seed_count),
            "--rng-seed",
            str(args.rng_seed),
            "--target-manifest",
            str(surge_manifest),
            "--surge-target",
            args.surge_target,
            "--trace-source",
            "vcs-native-abi",
            "--require-paper-native",
        ],
    )
    return commands


def write_campaign_manifest(paths: CampaignPaths, testcases: list[Testcase], commands: list[dict[str, Any]], args: argparse.Namespace) -> Path:
    rows = [
        {
            "method": item["method"],
            "command": command_to_text(item["command"]),
            "env": ";".join(f"{key}={value}" for key, value in sorted(item.get("env", {}).items())),
            "work_dir": str(item["work_dir"]),
            "output_csv": str(item["output_csv"]),
            "output_json": str(item["output_json"]),
            "coverage_name": item["coverage_name"],
            "formal_guard": item["formal_guard"],
        }
        for item in commands
    ]
    csv_path = paths.manifests / "campaign_commands.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=CAMPAIGN_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    payload = {
        "campaign_root": str(paths.root),
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "testcase_count": len(testcases),
        "exec_budget": args.exec_budget,
        "timeout_sec": args.timeout_sec,
        "target_min_wall_time_sec": args.target_min_wall_time_sec,
        "rng_seed": args.rng_seed,
        "build_mode": args.build_mode,
        "sfuzz_num_cores": args.sfuzz_num_cores,
        "commands": rows,
    }
    json_path = paths.manifests / "campaign_manifest.json"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    shell_path = paths.scripts / "run_all.sh"
    shell_lines = ["#!/usr/bin/env bash", "set -euo pipefail", ""]
    for item in commands:
        env_prefix = " ".join(f"{key}={shlex.quote(value)}" for key, value in sorted(item.get("env", {}).items()))
        shell_lines.append(f"{env_prefix + ' ' if env_prefix else ''}{command_to_text(item['command'])}")
    shell_path.write_text("\n".join(shell_lines) + "\n", encoding="utf-8")
    shell_path.chmod(0o755)
    return json_path


def validate_prepare(args: argparse.Namespace, testcases: list[Testcase]) -> None:
    if len(testcases) < args.min_testcases:
        raise ValueError(f"need at least {args.min_testcases} runnable testcases, found {len(testcases)}")
    if args.exec_budget < 1000:
        raise ValueError("formal four-fuzzer campaign requires --exec-budget >= 1000")
    if args.timeout_sec < 120:
        raise ValueError("formal four-fuzzer campaign requires --timeout-sec >= 120")
    if args.target_min_wall_time_sec < 60:
        raise ValueError("formal SFuzz campaign requires --target-min-wall-time-sec >= 60")
    require_file(args.direct_metadata.expanduser())
    require_file(args.surge_target_manifest.expanduser())


def run_commands(commands: list[dict[str, Any]], stop_on_failure: bool) -> int:
    overall = 0
    for item in commands:
        method = item["method"]
        command = item["command"]
        log_path = Path(item["work_dir"]).parent / "driver.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        print(f"[campaign] running {method}: {command_to_text(command)}", flush=True)
        env = os.environ.copy()
        env.update(item.get("env", {}))
        with log_path.open("w", encoding="utf-8") as log_file:
            result = subprocess.run(command, cwd=SFUZZ_HOME, text=True, stdout=log_file, stderr=subprocess.STDOUT, env=env)
        if result.returncode != 0:
            overall = result.returncode or 1
            print(f"[campaign] {method} failed, see {log_path}", flush=True)
            if stop_on_failure:
                return overall
        else:
            print(f"[campaign] {method} complete, log={log_path}", flush=True)
    return overall


def bool_text(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes"}


def numeric(value: Any) -> float | None:
    if value in {None, ""}:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def coverage_pair(row: dict[str, str]) -> tuple[float | None, float | None]:
    candidates = [
        ("accumulated_covered_bits", "common_coverage_total"),
        ("total_covered", "rfuzz_mux_total"),
        ("accumulated_covered_bits", "total"),
        ("global_ancestor_coverage", "coverage_total"),
    ]
    for covered_key, total_key in candidates:
        covered = numeric(row.get(covered_key))
        total = numeric(row.get(total_key))
        if covered is not None and total and total > 0:
            return covered, total
    value = numeric(row.get("common_coverage_value") or row.get("coverage_value"))
    if value is not None:
        return value, 100.0
    return None, None


def row_is_mutation(row: dict[str, str]) -> bool:
    markers = [
        row.get("mutation_index", ""),
        row.get("mutation", ""),
        row.get("mutation_kind", ""),
        row.get("round", ""),
    ]
    text = ";".join(str(item) for item in markers).lower()
    return bool(text) and not any(token in text for token in ["initial", "bootstrap", "seed", "initial-workload"])


def command_log_cycle_violation(row: dict[str, str]) -> bool:
    if bool_text(row.get("command_has_cycles_arg")) or bool_text(row.get("command_has_max_cycles_plusarg")):
        return True
    command_log = row.get("command_log_path") or ""
    if not command_log:
        return False
    path = Path(command_log)
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8", errors="replace")
    return "--cycles=" in text or "+max-cycles=5000" in text


def summarize_csv(method: str, csv_path: Path) -> dict[str, Any]:
    if not csv_path.is_file():
        return {
            "method": method,
            "result_csv": str(csv_path),
            "rows": 0,
            "mutation_rows": 0,
            "mutation_ratio": 0.0,
            "paper_faithful_rows": 0,
            "timed_out_rows": 0,
            "bug_rows": 0,
            "no_cycle_limit_rows": 0,
            "command_cycle_violations": 0,
            "final_covered": "",
            "final_total": "",
            "final_percent": "",
            "auc_exec_percent": "",
            "notes": "missing result CSV",
        }
    with csv_path.open(newline="", encoding="utf-8") as input_file:
        rows = list(csv.DictReader(input_file))
    coverage_percent: list[float] = []
    final_covered: float | None = None
    final_total: float | None = None
    for row in rows:
        covered, total = coverage_pair(row)
        if covered is None or not total:
            continue
        final_covered, final_total = covered, total
        coverage_percent.append(100.0 * covered / total)
    auc = sum(coverage_percent) / len(coverage_percent) if coverage_percent else ""
    final_percent = 100.0 * final_covered / final_total if final_covered is not None and final_total else ""
    mutation_rows = sum(1 for row in rows if row_is_mutation(row))
    return {
        "method": method,
        "result_csv": str(csv_path),
        "rows": len(rows),
        "mutation_rows": mutation_rows,
        "mutation_ratio": round(mutation_rows / len(rows), 6) if rows else 0.0,
        "paper_faithful_rows": sum(1 for row in rows if bool_text(row.get("paper_faithful"))),
        "timed_out_rows": sum(1 for row in rows if bool_text(row.get("timed_out"))),
        "bug_rows": sum(1 for row in rows if bool_text(row.get("bug_triggered")) or bool_text(row.get("design_bug"))),
        "no_cycle_limit_rows": sum(1 for row in rows if bool_text(row.get("no_max_cycle_limit"))),
        "command_cycle_violations": sum(1 for row in rows if command_log_cycle_violation(row)),
        "final_covered": int(final_covered) if final_covered is not None and float(final_covered).is_integer() else final_covered or "",
        "final_total": int(final_total) if final_total is not None and float(final_total).is_integer() else final_total or "",
        "final_percent": round(final_percent, 6) if final_percent != "" else "",
        "auc_exec_percent": round(auc, 6) if auc != "" else "",
        "notes": "",
    }


def aggregate(paths: CampaignPaths) -> Path:
    rows = []
    for method in ["sfuzz", "rfuzz", "directfuzz", "surgefuzz"]:
        rows.append(summarize_csv(method, paths.results / method / "results.csv"))
    output_json = paths.results / "aggregate_summary.json"
    output_csv = paths.results / "aggregate_summary.csv"
    write_table(rows, output_json, output_csv, SUMMARY_FIELDS, {"campaign_root": str(paths.root)})
    report = paths.reports / "t2_four_fuzzer_summary.md"
    lines = ["# T2 四工具长运行对比摘要", "", f"campaign: `{paths.root}`", "", "| method | rows | mutation rows | final coverage | AUC | notes |", "|---|---:|---:|---:|---:|---|"]
    for row in rows:
        final = ""
        if row["final_covered"] != "" and row["final_total"] != "":
            final = f"{row['final_covered']} / {row['final_total']} ({row['final_percent']}%)"
        lines.append(
            f"| {row['method']} | {row['rows']} | {row['mutation_rows']} | {final} | {row['auc_exec_percent']} | {row['notes']} |"
        )
    lines.append("")
    lines.append("正式结论需要逐项检查 command_cycle_violations=0、rows>=1000、mutation_ratio>=0.8。")
    report.write_text("\n".join(lines), encoding="utf-8")
    return output_csv


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare, run, and aggregate a formal T2 four-fuzzer LinkNan campaign")
    parser.add_argument("--phase", choices=["prepare", "run", "aggregate", "all"], default="prepare")
    parser.add_argument("--campaign-root", type=Path, default=None)
    parser.add_argument("--manifest", type=Path, default=SFUZZ_HOME / "benchmarks" / "linknan" / "phase1_corpus_manifest.csv")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--linknan-root", type=Path, default=SFUZZ_HOME.parent / "LinkNan")
    parser.add_argument("--direct-metadata", type=Path, default=SFUZZ_HOME / "work" / "directfuzz-native" / "static_metadata_per_instance_full.csv")
    parser.add_argument("--surge-target-manifest", type=Path, default=SFUZZ_HOME / "config" / "surgefuzz_targets.toml")
    parser.add_argument("--direct-target-instance", default=DEFAULT_DIRECT_TARGET)
    parser.add_argument("--surge-target", default="memblock_load_miss")
    parser.add_argument("--limit", type=int, default=120, help="maximum testcase count selected from manifest")
    parser.add_argument("--min-testcases", type=int, default=100)
    parser.add_argument("--exec-budget", type=int, default=1000)
    parser.add_argument("--timeout-sec", type=int, default=120)
    parser.add_argument("--target-min-wall-time-sec", type=int, default=60)
    parser.add_argument("--rng-seed", type=int, default=20260605)
    parser.add_argument("--sfuzz-scheduler", choices=["weighted-innovation", "semantic-bandit"], default="semantic-bandit")
    parser.add_argument("--surge-initial-seed-count", type=int, default=1)
    parser.add_argument(
        "--build-mode",
        choices=["auto", "skip", "build", "rebuild"],
        default="auto",
        help="auto lets each runner rebuild simv when the requested coverage ABI does not match the current build",
    )
    parser.add_argument("--build-chisel", action="store_true")
    parser.add_argument("--build-timeout-sec", type=int, default=3600)
    parser.add_argument("--simv-args", default="")
    parser.add_argument("--sfuzz-num-cores", type=int, default=2)
    parser.add_argument("--keep-going", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    campaign_root = args.campaign_root or (SFUZZ_HOME / "campaigns" / f"t2-long-four-fuzzer-{now_slug()}")
    paths = CampaignPaths.create(campaign_root.expanduser().resolve())
    if args.phase in {"prepare", "all"}:
        testcases = load_testcases(args.manifest.expanduser(), args.limit)
        validate_prepare(args, testcases)
        sfuzz_list, workload_list, selected_manifest = write_seed_lists(paths, testcases)
        commands = campaign_commands(args, paths, sfuzz_list, workload_list)
        manifest_json = write_campaign_manifest(paths, testcases, commands, args)
        print(f"prepared {len(testcases)} testcases")
        print(f"selected manifest: {selected_manifest}")
        print(f"campaign manifest: {manifest_json}")
    else:
        command_manifest = paths.manifests / "campaign_commands.csv"
        require_file(command_manifest)
        commands = []
        with command_manifest.open(newline="", encoding="utf-8") as input_file:
            for row in csv.DictReader(input_file):
                commands.append(
                    {
                        "method": row["method"],
                        "command": shlex.split(row["command"]),
                        "env": dict(
                            item.split("=", 1) for item in row.get("env", "").split(";") if item and "=" in item
                        ),
                        "work_dir": Path(row["work_dir"]),
                        "output_csv": Path(row["output_csv"]),
                        "output_json": Path(row["output_json"]),
                        "coverage_name": row["coverage_name"],
                        "formal_guard": row["formal_guard"],
                    }
                )
    if args.phase in {"run", "all"}:
        status = run_commands(commands, stop_on_failure=not args.keep_going)
        if status != 0:
            return status
    if args.phase in {"aggregate", "all"}:
        summary = aggregate(paths)
        print(f"aggregate summary: {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
