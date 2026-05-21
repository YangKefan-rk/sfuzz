from __future__ import annotations

from typing import Any

from ..common import (
    slugify,
    write_table,
)
from ..config import VcsContext
from ..seeds import collect_seed_paths, read_seed_metadata_name, seed_category
from ..vcs import (
    build_simv_if_needed,
    collect_vcs_coverage,
    common_coverage_backend,
    run_vcs_seed,
    scan_vcs_logs,
)


BASELINE_FIELDS = [
    "fuzzer",
    "seed_name",
    "seed_category",
    "seed_path",
    "comparison_tier",
    "paper_faithful",
    "coverage_backend",
    "common_coverage_backend",
    "common_coverage_name",
    "common_coverage_value",
    "common_coverage_source",
    "common_coverage_status",
    "required_native_abi",
    "wall_time_sec",
    "vcs_cycles",
    "vcs_cpu_time_sec",
    "vcs_sim_time_ps",
    "max_cycle_exceeded",
    "run_outcome",
    "t0_smoke_pass",
    "exit_code",
    "vcs_report_seen",
    "sfuz_expansion_seen",
    "good_trap_seen",
    "bug_triggered",
    "bug_reasons",
    "coverage_name",
    "coverage_value",
    "coverage_source",
    "coverage_status",
    "log_path",
    "assert_log_path",
    "command_log_path",
    "case_dir",
    "case_name",
    "timed_out",
    "infrastructure_error",
]


def run_sfuzz(args: Any, ctx: VcsContext) -> int:
    work_dir = args.work_dir.expanduser().resolve()
    runs_dir = work_dir / "runs"
    logs_dir = work_dir / "logs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    seeds = collect_seed_paths(args.seed, args.seed_list, args.seed_dir, work_dir, args.limit, True, "sfuzz-smoke")
    build_simv_if_needed(args, ctx, work_dir)

    rows: list[dict[str, Any]] = []
    for index, seed in enumerate(seeds, 1):
        seed_name = read_seed_metadata_name(seed)
        category = seed_category(seed, seed_name)
        case_name = f"{slugify(args.case_prefix)}-{index:04d}-{slugify(seed_name)}"
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
        if result.timed_out and "timeout" not in info.bug_reasons:
            info.bug_reasons.append("timeout")
            info.bug_triggered = True

        infrastructure_error = result.error
        if result.returncode != 0 and not infrastructure_error and not info.bug_triggered:
            infrastructure_error = f"command returned non-zero exit code {result.returncode}"
        if not run_log.is_file() and not infrastructure_error:
            infrastructure_error = "run.log missing"

        coverage = collect_vcs_coverage(args, case_dir, ctx.sim_dir)
        coverage_backend = common_coverage_backend(coverage)
        comparison_tier = "T1_common_backend" if coverage_backend == "sfuzz_firrtl" else "T0_smoke"
        paper_faithful = False
        required_native_abi = "sfuzz_linknan_native_bitmap"
        t0_smoke_pass = (
            result.returncode == 0
            and info.sfuz_expansion_seen
            and info.vcs_report_seen
            and not info.bug_triggered
            and not infrastructure_error
        )
        if infrastructure_error:
            run_outcome = "infrastructure_error"
        elif result.timed_out:
            run_outcome = "timeout"
        elif info.bug_triggered:
            run_outcome = "bug_triggered"
        elif info.good_trap_seen:
            run_outcome = "good_trap"
        elif info.max_cycle_exceeded:
            run_outcome = "max_cycle_reached"
        elif info.finish_seen:
            run_outcome = "finished"
        else:
            run_outcome = "unknown"
        rows.append(
            {
                "fuzzer": "sfuzz",
                "seed_name": seed_name,
                "seed_category": category,
                "seed_path": str(seed),
                "comparison_tier": comparison_tier,
                "paper_faithful": paper_faithful,
                "coverage_backend": coverage_backend,
                "common_coverage_backend": coverage_backend,
                "common_coverage_name": coverage.coverage_name,
                "common_coverage_value": coverage.coverage_value,
                "common_coverage_source": coverage.coverage_source,
                "common_coverage_status": coverage.coverage_status,
                "required_native_abi": required_native_abi,
                "wall_time_sec": round(result.wall_time_sec, 3),
                "vcs_cycles": info.cycles or ctx.cycles,
                "vcs_cpu_time_sec": info.vcs_cpu_time_sec,
                "vcs_sim_time_ps": info.vcs_sim_time_ps,
                "max_cycle_exceeded": info.max_cycle_exceeded,
                "run_outcome": run_outcome,
                "t0_smoke_pass": t0_smoke_pass,
                "exit_code": result.returncode,
                "vcs_report_seen": info.vcs_report_seen,
                "sfuz_expansion_seen": info.sfuz_expansion_seen,
                "good_trap_seen": info.good_trap_seen,
                "bug_triggered": info.bug_triggered,
                "bug_reasons": info.bug_reasons,
                "coverage_name": coverage.coverage_name,
                "coverage_value": coverage.coverage_value,
                "coverage_source": coverage.coverage_source,
                "coverage_status": coverage.coverage_status,
                "log_path": str(run_log),
                "assert_log_path": str(assert_log),
                "command_log_path": result.command_log_path,
                "case_dir": str(case_dir),
                "case_name": case_name,
                "timed_out": result.timed_out,
                "infrastructure_error": infrastructure_error,
            }
        )
        print(f"[{index}/{len(seeds)}] sfuzz exit={result.returncode} log={run_log}", flush=True)

    write_table(
        rows,
        args.output_json or work_dir / "results.json",
        args.output_csv or work_dir / "results.csv",
        BASELINE_FIELDS,
        {"fuzzer": "sfuzz"},
    )
    return 0
