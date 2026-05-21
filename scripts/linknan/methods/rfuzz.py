from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from ..common import (
    append_notes,
    popcount_bytes,
    write_table,
)
from ..config import VcsContext
from ..seeds import seed_from_raw_hex
from ..vcs import build_simv_if_needed, collect_vcs_coverage, run_vcs_seed, scan_vcs_logs


RFUZZ_FIELDS = [
    "fuzzer",
    "seed",
    "seed_path",
    "wall_time_sec",
    "cycles",
    "exit_code",
    "coverage_backend",
    "coverage_value",
    "covered",
    "total",
    "toggle_bits",
    "vcs_cpu_time_sec",
    "vcs_sim_time_ps",
    "log_path",
    "paper_faithful",
    "required_native_abi",
    "notes",
]


def parse_firrtl_annotated_dir(path: Path) -> dict[str, Any]:
    line_covered = line_uncovered = toggle_covered = toggle_uncovered = files = 0
    line_cov_patterns = [re.compile(r"^\s*(\d+)\s+if\b"), re.compile(r"^\s*(\d+)\s+end else\b")]
    line_uncov_patterns = [re.compile(r"^\s*(%0+)\s+if\b"), re.compile(r"^\s*(%0+)\s+end else\b")]
    toggle_cov_patterns = [
        re.compile(r"^\s*(\d+)\s+reg\b"),
        re.compile(r"^\s*(\d+)\s+wire\b"),
        re.compile(r"^\s*(\d+)\s+input\b"),
        re.compile(r"^\s*(\d+)\s+output\b"),
    ]
    toggle_uncov_patterns = [
        re.compile(r"^\s*(%0+)\s+reg\b"),
        re.compile(r"^\s*(%0+)\s+wire\b"),
        re.compile(r"^\s*(%0+)\s+input\b"),
        re.compile(r"^\s*(%0+)\s+output\b"),
    ]
    for source in path.rglob("*"):
        if source.suffix not in {".v", ".sv"} or "_annotated" not in source.name:
            continue
        files += 1
        for line in source.read_text(encoding="utf-8", errors="replace").splitlines():
            if any(pattern.search(line) for pattern in line_cov_patterns):
                line_covered += 1
            elif any(pattern.search(line) for pattern in line_uncov_patterns):
                line_uncovered += 1
            elif any(pattern.search(line) for pattern in toggle_cov_patterns):
                toggle_covered += 1
            elif any(pattern.search(line) for pattern in toggle_uncov_patterns):
                toggle_uncovered += 1
    line_total = line_covered + line_uncovered
    toggle_total = toggle_covered + toggle_uncovered
    covered = toggle_covered if toggle_total else line_covered
    total = toggle_total if toggle_total else line_total
    return {
        "backend": "firrtl_annotated_diagnostic",
        "coverage_value": 100.0 * covered / total if total else None,
        "covered": covered or None,
        "total": total or None,
        "files": files,
    }


def run_rfuzz(args: Any, ctx: VcsContext) -> int:
    work_dir = args.work_dir.expanduser().resolve()
    runs_dir = work_dir / "runs"
    logs_dir = work_dir / "logs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    if args.seed:
        seed = Path(args.seed[0]).expanduser().resolve()
        raw = seed.read_bytes()
    else:
        seed, raw = seed_from_raw_hex(args.raw_hex, work_dir, args.case_name)
    build_simv_if_needed(args, ctx, work_dir)

    result, case_dir, run_log, assert_log = run_vcs_seed(
        seed=seed,
        case_name=args.case_name,
        runs_dir=runs_dir,
        logs_dir=logs_dir,
        ctx=ctx,
        timeout_sec=args.timeout_sec,
        cov=args.cov,
        simv_args=args.simv_args,
    )
    info = scan_vcs_logs(run_log, assert_log, ctx.cycles)
    coverage_backend = "vcs_log_only"
    coverage_value = covered = total = toggle_bits = ""
    notes = [
        "真实 LinkNan VCS 已运行",
        "当前 raw bytes 通过 SFUZ core0 payload 进入 VCS，不是 RFuzz 论文定义的逐周期顶层 pin 输入",
        "必须接入论文定义的 RFuzz mux-select 覆盖/反馈 ABI 后，才能作为 paper-faithful RFuzz 数据",
    ]
    if args.rfuzz_toggle_bitmap:
        bitmap = args.rfuzz_toggle_bitmap.expanduser().read_bytes()
        coverage_backend = "rfuzz_mux_select_external_bitmap"
        covered = popcount_bytes(bitmap)
        total = args.rfuzz_toggle_total or len(bitmap) * 8
        coverage_value = round(100.0 * covered / total, 6) if total else ""
        toggle_bits = bitmap.hex()
        notes.append("已提供外部 RFuzz mux-select bitmap")
    elif args.firrtl_annotated_dir:
        parsed = parse_firrtl_annotated_dir(args.firrtl_annotated_dir.expanduser())
        coverage_backend = parsed["backend"]
        coverage_value = parsed["coverage_value"]
        covered = parsed["covered"]
        total = parsed["total"]
        notes.append(f"annotated_files={parsed['files']}")
    elif args.cov:
        cov = collect_vcs_coverage(args, case_dir, ctx.sim_dir)
        coverage_backend = cov.coverage_name or "vcs_builtin_coverage"
        coverage_value = cov.coverage_value
        notes.append(cov.coverage_status)

    row = {
        "fuzzer": "rfuzz",
        "seed": hashlib.sha256(raw).hexdigest()[:16],
        "seed_path": str(seed),
        "wall_time_sec": round(result.wall_time_sec, 6),
        "cycles": info.cycles or ctx.cycles,
        "exit_code": result.returncode,
        "coverage_backend": coverage_backend,
        "coverage_value": coverage_value,
        "covered": covered,
        "total": total,
        "toggle_bits": toggle_bits,
        "vcs_cpu_time_sec": info.vcs_cpu_time_sec,
        "vcs_sim_time_ps": info.vcs_sim_time_ps,
        "log_path": str(run_log),
        "paper_faithful": coverage_backend == "rfuzz_mux_select_external_bitmap",
        "required_native_abi": "" if coverage_backend == "rfuzz_mux_select_external_bitmap" else "rfuzz_pin_stream_and_mux_select_toggle",
        "notes": append_notes(notes, {"sfuz_seen": info.sfuz_expansion_seen, "vcs_report": info.vcs_report_seen}),
    }
    write_table(
        [row],
        args.output_json or work_dir / "result.json",
        args.output_csv or work_dir / "result.csv",
        RFUZZ_FIELDS,
        {"fuzzer": "rfuzz"},
    )
    return 0
