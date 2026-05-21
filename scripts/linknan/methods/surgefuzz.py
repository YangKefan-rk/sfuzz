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
from ..vcs import build_simv_if_needed, run_vcs_seed, scan_vcs_logs


SURGEFUZZ_FIELDS = [
    "fuzzer",
    "seed",
    "annotation_type",
    "target_signal_or_group",
    "best_score",
    "energy",
    "ancestor_coverage_bits",
    "new_coverage",
    "coverage_backend",
    "wall_time_sec",
    "cycles",
    "exit_code",
    "log_path",
    "paper_faithful",
    "required_native_abi",
    "notes",
    "score_backend",
    "coverage_total",
    "coverage_covered",
    "coverage_acc",
]


def parse_annotation(raw: str) -> tuple[str, bool, str]:
    key, value = raw.split("=", 1)
    key_norm = re.sub(r"[\s_]", "", key).upper()
    value_norm = value.strip().strip('"').strip("'")
    if key_norm in {"SURGEFREQ", "FREQ"}:
        return "FREQ", value_norm not in {"0", "false", "False"}, "MAX"
    if key_norm in {"SURGECONSEC", "CONSEC"}:
        return "CONSEC", value_norm not in {"0", "false", "False"}, "MAX"
    if key_norm in {"SURGECOUNT", "COUNT"}:
        return "COUNT", True, value_norm.upper()
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
        rows = list(reader)
    values = [int(row[score_column], 0) for row in rows]
    dep_cols = [name for name in (reader.fieldnames or []) if name.startswith("dependent_")]
    dependents = [tuple(int(row[name], 0) for name in dep_cols) for row in rows]
    return values, dependents


def run_surgefuzz(args: Any, ctx: VcsContext) -> int:
    work_dir = args.work_dir.expanduser().resolve()
    runs_dir = work_dir / "vcs-runs"
    logs_dir = work_dir / "logs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    seeds = collect_seed_paths(args.seed, args.seed_list, args.seed_dir, work_dir, args.limit, True, "surgefuzz-smoke")
    build_simv_if_needed(args, ctx, work_dir)
    annotation = parse_annotation(args.annotation_type)
    rows: list[dict[str, Any]] = []
    for idx, seed in enumerate(seeds):
        case_name = f"{slugify(args.case_prefix)}-{idx:03d}-{slugify(seed.stem)}"
        result, _case_dir, run_log, assert_log = run_vcs_seed(
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
            backend = "dev_mock_score_trace" if args.trace_is_dev_mock else "surgefuzz_per_cycle_trace_csv"
            score_backend = backend
            notes = f"真实 LinkNan VCS 已运行;trace={trace}"
            paper_faithful = not args.trace_is_dev_mock
            required_native_abi = "" if paper_faithful else "surgefuzz_per_cycle_score_and_ancestor_coverage"
            if args.trace_is_dev_mock:
                notes += ";当前 trace 标记为 dev mock，仅用于调试数据管线，必须接入论文定义的 SurgeFuzz per-cycle score/ancestor coverage ABI"
        else:
            proof = [
                info.sfuz_expansion_seen,
                info.vcs_report_seen,
                bool(info.cycles),
                info.good_trap_seen,
            ]
            best_score = sum(1 for item in proof if item)
            energy = float(best_score * best_score)
            ancestor_states = set()
            backend = "vcs_log_health"
            score_backend = "vcs_log_health"
            paper_faithful = False
            required_native_abi = "surgefuzz_per_cycle_score_and_ancestor_coverage"
            notes = (
                "真实 LinkNan VCS 已运行;"
                "当前日志健康特征不是 SurgeFuzz 论文定义的 ancestor coverage;"
                "必须接入论文定义的 per-cycle score/ancestor coverage ABI"
            )
        rows.append(
            {
                "fuzzer": "surgefuzz",
                "seed": str(seed),
                "annotation_type": args.annotation_type,
                "target_signal_or_group": args.target_signal_or_group,
                "best_score": best_score,
                "energy": energy,
                "ancestor_coverage_bits": len(ancestor_states),
                "new_coverage": len(ancestor_states),
                "coverage_backend": backend,
                "wall_time_sec": round(result.wall_time_sec, 6),
                "cycles": info.cycles or ctx.cycles,
                "exit_code": result.returncode,
                "log_path": str(run_log),
                "paper_faithful": paper_faithful,
                "required_native_abi": required_native_abi,
                "notes": append_notes(notes, {"sfuz_seen": info.sfuz_expansion_seen, "vcs_report": info.vcs_report_seen}),
                "score_backend": score_backend,
                "coverage_total": "",
                "coverage_covered": "",
                "coverage_acc": "",
            }
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
