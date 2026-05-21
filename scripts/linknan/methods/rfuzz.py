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
    "runner_abi",
    "input_model",
    "toggle_bitmap_source",
    "valid_source",
    "valid",
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

MISSING_RAW_PIN_STREAM = "rfuzz_raw_top_pin_stream_input_abi"
MISSING_MUX_TOGGLE = "rfuzz_vcs_mux_select_toggle_bitmap_abi"
MISSING_VALID = "rfuzz_validity_abi_or_unconstrained_proof"
MISSING_FEEDBACK_LOOP = "rfuzz_total_and_valid_corpus_feedback_loop"
MISSING_NATIVE_RUNNER = "rfuzz_vcs_native_runner_abi"


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


def parse_bool_choice(value: str) -> bool | None:
    if value == "true":
        return True
    if value == "false":
        return False
    return None


def rfuzz_valid_value(args: Any) -> bool | str:
    if args.rfuzz_valid_source == "unconstrained":
        return True
    parsed = parse_bool_choice(args.rfuzz_valid)
    return parsed if parsed is not None else "unknown"


def required_native_abi(args: Any, has_native_bitmap: bool) -> list[str]:
    missing: list[str] = [MISSING_NATIVE_RUNNER]
    if args.rfuzz_input_model != "raw-pin-stream":
        missing.append(MISSING_RAW_PIN_STREAM)
    if not has_native_bitmap:
        missing.append(MISSING_MUX_TOGGLE)
    valid_known = args.rfuzz_valid_source == "unconstrained" or (
        args.rfuzz_valid_source == "vcs-native-abi"
        and parse_bool_choice(args.rfuzz_valid) is not None
    )
    if not valid_known:
        missing.append(MISSING_VALID)
    if not args.rfuzz_campaign_feedback:
        missing.append(MISSING_FEEDBACK_LOOP)
    return missing


def run_rfuzz(args: Any, ctx: VcsContext) -> int:
    work_dir = args.work_dir.expanduser().resolve()
    runs_dir = work_dir / "runs"
    logs_dir = work_dir / "logs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    input_model = args.rfuzz_input_model
    if args.seed:
        seed = Path(args.seed[0]).expanduser().resolve()
        raw = seed.read_bytes()
        if input_model == "sfuz-core0-payload":
            input_model = "sfuz-seed" if seed.suffix == ".sfuz" else "linknan-workload-file"
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
    runner_abi = "linknan-workload-simv-run"
    coverage_backend = "vcs_log_only"
    coverage_value = covered = total = toggle_bits = ""
    notes = [
        "真实 LinkNan VCS 已运行",
        "当前 RFuzz 入口通过 LinkNan workload 路径进入 VCS，不是 RFuzz 论文定义的逐周期顶层 pin 输入",
        "必须接入论文定义的 RFuzz mux-select 覆盖/反馈 ABI 后，才能作为 paper-faithful RFuzz 数据",
    ]
    has_native_bitmap = False
    toggle_bitmap_source = "absent"
    if args.rfuzz_toggle_bitmap:
        toggle_bitmap_source = args.rfuzz_toggle_bitmap_source
        bitmap = args.rfuzz_toggle_bitmap.expanduser().read_bytes()
        has_native_bitmap = args.rfuzz_toggle_bitmap_source == "vcs-native-abi"
        coverage_backend = (
            "rfuzz_mux_select_vcs_native_abi"
            if has_native_bitmap
            else "rfuzz_mux_select_external_bitmap_diagnostic"
        )
        covered = popcount_bytes(bitmap)
        total = args.rfuzz_toggle_total or len(bitmap) * 8
        coverage_value = round(100.0 * covered / total, 6) if total else ""
        toggle_bits = bitmap.hex()
        notes.append(f"已提供 RFuzz mux-select bitmap source={args.rfuzz_toggle_bitmap_source}")
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

    missing_native_abi = required_native_abi(args, has_native_bitmap)
    paper_faithful = not missing_native_abi
    if input_model == "sfuz-core0-payload":
        notes.append("LinkNan 入口使用生成的 SFUZ core0 payload，不是 RFuzz raw pin-stream")
    elif input_model == "sfuz-seed":
        notes.append("LinkNan 入口使用现有 SFUZ 程序镜像/内存 payload，不是 RFuzz raw pin-stream")
    elif input_model == "linknan-workload-file":
        notes.append("LinkNan 入口使用现有 workload 文件，不是 RFuzz raw pin-stream")
    notes.append("当前 scripts/linknan RFuzz runner 仍通过 xmake simv-run --workload 执行，缺少 native RFuzz VCS runner ABI")
    if coverage_backend in {"vcs_log_only", "vcs_builtin_coverage", "firrtl_annotated_diagnostic"}:
        notes.append("该 coverage_backend 只能诊断 VCS 健康或普通覆盖，不能充当 RFuzz mux-select feedback")
    if args.rfuzz_toggle_bitmap and not has_native_bitmap:
        notes.append("外部 bitmap 未声明为 VCS native RFuzz ABI 导出，不能作为 paper-faithful 结果")

    row = {
        "fuzzer": "rfuzz",
        "seed": hashlib.sha256(raw).hexdigest()[:16],
        "seed_path": str(seed),
        "runner_abi": runner_abi,
        "input_model": input_model,
        "toggle_bitmap_source": toggle_bitmap_source,
        "valid_source": args.rfuzz_valid_source,
        "valid": rfuzz_valid_value(args),
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
        "paper_faithful": paper_faithful,
        "required_native_abi": ";".join(missing_native_abi),
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
