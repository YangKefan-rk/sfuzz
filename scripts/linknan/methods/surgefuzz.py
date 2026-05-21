from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Any

from ..common import (
    append_notes,
    slugify,
    write_table,
)
from ..config import VcsContext
from ..seeds import collect_seed_paths
from ..vcs import build_simv_if_needed, collect_vcs_coverage, common_coverage_backend, run_vcs_seed, scan_vcs_logs


REQUIRED_SURGE_NATIVE_ABI = "surgefuzz_per_cycle_score_and_ancestor_coverage"
RUNNER_ABI = "linknan-workload-simv-run"

SURGEFUZZ_FIELDS = [
    "fuzzer",
    "seed",
    "case_name",
    "comparison_tier",
    "runner_abi",
    "annotation_type",
    "target_signal_or_group",
    "best_score",
    "energy",
    "ancestor_coverage_bits",
    "new_coverage",
    "coverage_backend",
    "common_coverage_backend",
    "common_coverage_name",
    "common_coverage_value",
    "common_coverage_source",
    "common_coverage_status",
    "score_backend",
    "trace_source",
    "trace_path",
    "score_column",
    "wall_time_sec",
    "cycles",
    "max_cycle_exceeded",
    "exit_code",
    "vcs_report_seen",
    "sfuz_expansion_seen",
    "good_trap_seen",
    "bug_triggered",
    "bug_reasons",
    "vcs_cpu_time_sec",
    "vcs_sim_time_ps",
    "log_path",
    "assert_log_path",
    "command_log_path",
    "case_dir",
    "timed_out",
    "infrastructure_error",
    "paper_faithful",
    "required_native_abi",
    "notes",
    "coverage_total",
    "coverage_covered",
    "coverage_acc",
]


def parse_annotation(raw: str) -> tuple[str, bool, str]:
    key, value = raw.split("=", 1) if "=" in raw else (raw, "1")
    key_norm = re.sub(r"[\s_]", "", key).upper()
    value_norm = value.strip().strip('"').strip("'")
    if key_norm in {"SURGEFREQ", "FREQ"}:
        return "FREQ", value_norm not in {"0", "false", "False"}, "MAX"
    if key_norm in {"SURGECONSEC", "CONSEC"}:
        return "CONSEC", value_norm not in {"0", "false", "False"}, "MAX"
    if key_norm in {"SURGECOUNT", "COUNT"}:
        direction = value_norm.upper()
        if direction == "1":
            direction = "MAX"
        elif direction == "0":
            direction = "MIN"
        return "COUNT", True, direction
    raise ValueError(f"unsupported SurgeFuzz annotation: {raw}")


def score_series(kind: str, active: bool, direction: str, values: list[int], window: int = 256) -> list[int]:
    scores: list[int] = []
    fifo: list[int] = []
    consec = 0
    for value in values:
        if kind == "FREQ":
            bit = int((value != 0) == active)
            fifo.append(bit)
            if len(fifo) > window:
                fifo.pop(0)
            scores.append(sum(fifo))
        elif kind == "CONSEC":
            if (value != 0) == active:
                consec += 1
            else:
                consec = 0
            scores.append(consec)
        else:
            scores.append(value if direction == "MAX" else (2**32 - 1 - value))
    return scores


def load_surge_trace(path: Path, score_column: str) -> tuple[list[int], list[tuple[int, ...]]]:
    with path.open(newline="", encoding="utf-8") as input_file:
        reader = csv.DictReader(input_file)
        if reader.fieldnames is None:
            raise ValueError(f"{path}: CSV is missing a header")
        if score_column not in reader.fieldnames:
            raise ValueError(f"{path}: CSV is missing score column {score_column!r}")
        rows = list(reader)
    values = [int(row[score_column], 0) for row in rows]
    dep_cols = [name for name in (reader.fieldnames or []) if name.startswith("dependent_")]
    dependents = [tuple(int(row[name], 0) for name in dep_cols) for row in rows]
    return values, dependents


def trace_backend(trace_source: str) -> tuple[str, bool, str]:
    if trace_source == "vcs-native-abi":
        return "surgefuzz_vcs_native_abi_trace", True, ""
    if trace_source == "dev-mock":
        return (
            "dev_mock_score_trace",
            False,
            REQUIRED_SURGE_NATIVE_ABI,
        )
    return (
        "surgefuzz_offline_trace_csv",
        False,
        REQUIRED_SURGE_NATIVE_ABI,
    )


def run_surgefuzz(args: Any, ctx: VcsContext) -> int:
    work_dir = args.work_dir.expanduser().resolve()
    runs_dir = work_dir / "vcs-runs"
    logs_dir = work_dir / "logs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    seeds = collect_seed_paths(args.seed, args.seed_list, args.seed_dir, work_dir, args.limit, True, "surgefuzz-smoke")
    if args.trace_is_dev_mock and args.trace_source == "vcs-native-abi":
        raise ValueError("--trace-is-dev-mock conflicts with --trace-source vcs-native-abi")
    build_simv_if_needed(args, ctx, work_dir)
    annotation = parse_annotation(args.annotation_type)
    seen_ancestor_states: set[tuple[int, ...]] = set()
    rows: list[dict[str, Any]] = []
    for idx, seed in enumerate(seeds):
        case_name = f"{slugify(args.case_prefix)}-{idx:03d}-{slugify(seed.stem)}"
        result, case_dir, run_log, assert_log = run_vcs_seed(
            seed=seed,
            case_name=case_name,
            runs_dir=runs_dir,
            logs_dir=logs_dir,
            ctx=ctx,
            timeout_sec=args.timeout_sec,
            cov=args.cov,
            simv_args=args.simv_args,
        )
        info = scan_vcs_logs(run_log, assert_log, ctx.cycles)
        common_coverage = collect_vcs_coverage(args, case_dir, ctx.sim_dir)
        common_backend = common_coverage_backend(common_coverage)
        if result.timed_out and "timeout" not in info.bug_reasons:
            info.bug_reasons.append("timeout")
            info.bug_triggered = True

        infrastructure_error = result.error
        if result.returncode != 0 and not infrastructure_error and not info.bug_triggered:
            infrastructure_error = f"command returned non-zero exit code {result.returncode}"
        if not run_log.is_file() and not infrastructure_error:
            infrastructure_error = "run.log missing"

        trace = None
        if args.score_trace_dir:
            candidate = args.score_trace_dir.expanduser() / f"{seed.stem}.csv"
            if candidate.is_file():
                trace = candidate
        if trace is not None:
            values, dependents = load_surge_trace(trace, args.score_column)
            scores = score_series(*annotation, values, args.freq_window)
            best_score = max(scores, default=0)
            energy = float(best_score * best_score)
            ancestor_states = {row for row in dependents}
            new_ancestor_states = ancestor_states - seen_ancestor_states
            seen_ancestor_states.update(ancestor_states)
            ancestor_coverage_bits: int | str = len(ancestor_states)
            new_coverage: int | str = len(new_ancestor_states)
            trace_source = "dev-mock" if args.trace_is_dev_mock else args.trace_source
            backend, paper_faithful, required_native_abi = trace_backend(trace_source)
            score_backend = backend
            trace_path = str(trace)
            comparison_tier = "T2_paper_faithful_native_feedback" if paper_faithful else "T0_trace_smoke"
            notes = f"真实 LinkNan VCS 已运行;trace={trace}"
            if trace_source != "vcs-native-abi":
                notes += (
                    ";当前 trace 未声明为 LinkNan/VCS native ABI 导出，"
                    "只能诊断 scoring/coverage 数据管线，不能作为论文 SurgeFuzz 结果"
                )
        else:
            best_score = ""
            energy = ""
            ancestor_coverage_bits = ""
            new_coverage = ""
            backend = "none"
            score_backend = "unavailable"
            trace_source = "no-trace"
            trace_path = ""
            comparison_tier = "T0_vcs_smoke"
            paper_faithful = False
            required_native_abi = REQUIRED_SURGE_NATIVE_ABI
            notes = (
                "真实 LinkNan VCS 已运行;"
                "未发现 coverage_target/dependent_* per-cycle trace;"
                "未用 VCS 日志健康特征冒充 SurgeFuzz score 或 ancestor coverage;"
                "必须接入论文定义的 per-cycle score/ancestor coverage ABI"
            )
        rows.append(
            {
                "fuzzer": "surgefuzz",
                "seed": str(seed),
                "case_name": case_name,
                "comparison_tier": comparison_tier,
                "runner_abi": RUNNER_ABI,
                "annotation_type": args.annotation_type,
                "target_signal_or_group": args.target_signal_or_group,
                "best_score": best_score,
                "energy": energy,
                "ancestor_coverage_bits": ancestor_coverage_bits,
                "new_coverage": new_coverage,
                "coverage_backend": backend,
                "common_coverage_backend": common_backend,
                "common_coverage_name": common_coverage.coverage_name,
                "common_coverage_value": common_coverage.coverage_value,
                "common_coverage_source": common_coverage.coverage_source,
                "common_coverage_status": common_coverage.coverage_status,
                "score_backend": score_backend,
                "trace_source": trace_source,
                "trace_path": trace_path,
                "score_column": args.score_column,
                "wall_time_sec": round(result.wall_time_sec, 6),
                "cycles": info.cycles or ctx.cycles,
                "max_cycle_exceeded": info.max_cycle_exceeded,
                "exit_code": result.returncode,
                "vcs_report_seen": info.vcs_report_seen,
                "sfuz_expansion_seen": info.sfuz_expansion_seen,
                "good_trap_seen": info.good_trap_seen,
                "bug_triggered": info.bug_triggered,
                "bug_reasons": info.bug_reasons,
                "vcs_cpu_time_sec": info.vcs_cpu_time_sec,
                "vcs_sim_time_ps": info.vcs_sim_time_ps,
                "log_path": str(run_log),
                "assert_log_path": str(assert_log),
                "command_log_path": result.command_log_path,
                "case_dir": str(case_dir),
                "timed_out": result.timed_out,
                "infrastructure_error": infrastructure_error,
                "paper_faithful": paper_faithful,
                "required_native_abi": required_native_abi,
                "notes": append_notes(notes, {"sfuz_seen": info.sfuz_expansion_seen, "vcs_report": info.vcs_report_seen}),
                "coverage_total": "",
                "coverage_covered": "",
                "coverage_acc": "",
            }
        )
        print(
            f"[{idx + 1}/{len(seeds)}] surgefuzz exit={result.returncode} "
            f"trace_source={trace_source} log={run_log}",
            flush=True,
        )
    write_table(
        rows,
        args.output_json or work_dir / "surgefuzz_results.json",
        args.output_csv or work_dir / "surgefuzz_results.csv",
        SURGEFUZZ_FIELDS,
        {"fuzzer": "surgefuzz"},
    )
    return 0


def write_dev_surge_profile(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "instrument.csv").write_text(
        "name,width,src,depth,reg_depth,is_ctrl,cell_name\n"
        "coverage,4,1'0,0,0,0\n"
        "coverage_target,1,\\mshr_valid,0,0,0\n"
        "dependent_0,1,\\mshr_valid,1,0,1,$mux\n"
        "dependent_1,2,\\mshr_state,2,1,0,$dff\n"
        "dependent_2,1,\\mshr_full,3,1,1,$dff\n",
        encoding="utf-8",
    )
    (output_dir / "smoke.csv").write_text(
        "cycle,dependent_0,dependent_1,dependent_2,coverage_target\n"
        "0,0,0,0,0\n"
        "1,1,1,0,1\n"
        "2,1,2,1,1\n"
        "3,0,3,1,0\n",
        encoding="utf-8",
    )
