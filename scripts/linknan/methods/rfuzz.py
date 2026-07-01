from __future__ import annotations

import hashlib
import json
import random
import re
from pathlib import Path
from typing import Any

from ..common import (
    append_notes,
    popcount_bytes,
    slugify,
    write_table,
)
from ..config import VcsContext
from ..rfuzz_abi import audit_linknan_rfuzz_abi
from ..seeds import parse_hex_blob
from ..workload_mutation import ELF_MAGIC, is_elf_bytes, linknan_loader_assertion, mutate_linknan_workload
from ..vcs import (
    assertion_failure,
    build_simv_if_needed,
    classify_infrastructure_error,
    collect_vcs_coverage,
    common_coverage_backend,
    design_bug,
    design_bug_reasons,
    run_vcs_seed,
    scan_vcs_logs,
    wall_timeout,
)


RFUZZ_FIELDS = [
    "fuzzer",
    "round",
    "seed",
    "parent_seed",
    "input_path",
    "input_size_bytes",
    "mutation",
    "mutation_model",
    "runner_abi",
    "requested_input_model",
    "actual_input_abi",
    "input_model",
    "raw_pin_stream_supported",
    "raw_pin_stream_reason",
    "top_input_pins",
    "fuzzable_input_pins",
    "pin_stream_driver_supported",
    "validity_supported",
    "deterministic_reset_model",
    "sparse_memory_model",
    "cycle_limit",
    "toggle_bitmap_source",
    "valid_source",
    "valid",
    "wall_time_sec",
    "cycles",
    "exit_code",
    "vcs_report_seen",
    "sfuz_expansion_seen",
    "max_cycle_exceeded",
    "bug_triggered",
    "bug_reasons",
    "invalid_input",
    "invalid_input_reason",
    "coverage_backend",
    "coverage_value",
    "covered",
    "total",
    "rfuzz_mux_covered",
    "rfuzz_mux_total",
    "rfuzz_new_bits",
    "new_total_coverage",
    "new_valid_coverage",
    "total_covered",
    "valid_covered",
    "coverage_growth",
    "corpus_size",
    "retained",
    "retention_reason",
    "toggle_bits",
    "common_coverage_backend",
    "common_coverage_name",
    "common_coverage_value",
    "common_coverage_source",
    "common_coverage_status",
    "vcs_cpu_time_sec",
    "vcs_sim_time_ps",
    "log_path",
    "assert_log_path",
    "command_log_path",
    "case_dir",
    "case_name",
    "timed_out",
    "wall_timeout",
    "design_bug",
    "assertion_failure",
    "design_bug_reasons",
    "infrastructure_error",
    "paper_faithful",
    "paper_faithful_scope",
    "required_native_abi",
    "notes",
]

MISSING_MUX_TOGGLE = "rfuzz_vcs_mux_select_toggle_bitmap_abi"
MISSING_VALID = "rfuzz_validity_abi_or_unconstrained_proof"
MISSING_WORKLOAD_RUNNER = "rfuzz_linknan_workload_runner_abi"

SFUZ_MAGIC = b"SFUZ"
WORKLOAD_SUFFIXES = {".bin", ".elf", ".gz", ".zst", ".zstd", ""}
INTERESTING_BYTES = [0x00, 0x01, 0x10, 0x20, 0x40, 0x7F, 0x80, 0xFF]


class RfuzzCoverageState:
    def __init__(self, max_coverage: int = 0) -> None:
        self.total_global = bytearray()
        self.valid_global = bytearray()
        self.max_coverage = max_coverage

    def _fit(self, local: bytes) -> bytes:
        if not local:
            return local
        if len(local) > len(self.total_global):
            extra = len(local) - len(self.total_global)
            self.total_global.extend(b"\x00" * extra)
            self.valid_global.extend(b"\x00" * extra)
        elif len(local) < len(self.total_global):
            local = local + b"\x00" * (len(self.total_global) - len(local))
        if self.max_coverage == 0:
            self.max_coverage = len(self.total_global) * 8
        return local

    def classify(self, local: bytes, valid: bool) -> dict[str, Any]:
        local = self._fit(local)
        new_total = bool(local) and has_new_bits(self.total_global, local)
        new_valid = bool(local) and valid and has_new_bits(self.valid_global, local)
        before = self.total_covered()
        if new_total:
            apply_bits(self.total_global, local)
        if new_valid:
            apply_bits(self.valid_global, local)
        after = self.total_covered()
        return {
            "new_total": new_total,
            "new_valid": new_valid,
            "total_covered": after,
            "valid_covered": self.valid_covered(),
            "growth": after - before,
            "total_points": self.max_coverage,
        }

    def total_covered(self) -> int:
        return popcount_bytes(bytes(self.total_global))

    def valid_covered(self) -> int:
        return popcount_bytes(bytes(self.valid_global))


def has_new_bits(global_bits: bytearray, local_bits: bytes) -> bool:
    return any((local & ~seen) != 0 for seen, local in zip(global_bits, local_bits))


def apply_bits(global_bits: bytearray, local_bits: bytes) -> None:
    for idx, value in enumerate(local_bits):
        global_bits[idx] |= value


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


def rfuzz_valid_value(args: Any, info: Any) -> tuple[bool | None, bool | str]:
    if args.rfuzz_valid_source == "linknan-workload":
        return True, True
    if args.rfuzz_valid_source == "unconstrained":
        return True, True
    parsed = parse_bool_choice(args.rfuzz_valid)
    if args.rfuzz_valid_source in {"manual", "vcs-native-abi"} and parsed is not None:
        return parsed, parsed
    if args.rfuzz_valid_source == "vcs-good-trap":
        return bool(info.good_trap_seen), bool(info.good_trap_seen)
    return None, "unknown"


def required_native_abi(args: Any, has_native_bitmap: bool, valid_known: bool) -> list[str]:
    missing: list[str] = []
    if getattr(args, "rfuzz_actual_input_abi", "") != "linknan-workload-binary-adapter":
        missing.append(MISSING_WORKLOAD_RUNNER)
    if not has_native_bitmap:
        missing.append(MISSING_MUX_TOGGLE)
    if not valid_known:
        missing.append(MISSING_VALID)
    return missing


def reject_sfuz_workload(path: Path, data: bytes) -> None:
    if path.suffix == ".sfuz" or data.startswith(SFUZ_MAGIC):
        raise ValueError(
            f"RFuzz LinkNan runner refuses SFUZ structured seeds as official input: {path}. "
            "Use a normal LinkNan workload .bin/ELF for processor-verification RFuzz runs."
        )


def workload_input_model(path: Path, data: bytes) -> str:
    if is_elf_bytes(data):
        return "elf-workload"
    suffix = path.suffix.lower()
    if suffix == ".gz":
        return "gzip-workload"
    if suffix in {".zst", ".zstd"}:
        return "zstd-workload"
    return "binary-workload"


def read_seed_list(seed_list: Path) -> list[Path]:
    base = seed_list.expanduser().resolve().parent
    seeds: list[Path] = []
    for raw_line in seed_list.expanduser().read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        path = Path(line).expanduser()
        seeds.append(path if path.is_absolute() else base / path)
    return seeds


def collect_initial_workloads(args: Any, ctx: VcsContext, work_dir: Path) -> list[tuple[Path, bytes, str]]:
    paths: list[Path] = []
    paths.extend(Path(item).expanduser() for item in args.seed)
    paths.extend(Path(item).expanduser() for item in getattr(args, "input", []))
    if args.seed_list:
        paths.extend(read_seed_list(args.seed_list))
    if args.seed_dir:
        seed_dir = args.seed_dir.expanduser().resolve()
        if not seed_dir.is_dir():
            raise FileNotFoundError(f"missing RFuzz workload seed directory: {seed_dir}")
        paths.extend(path for path in sorted(seed_dir.iterdir()) if path.is_file() and path.suffix.lower() in WORKLOAD_SUFFIXES)

    if not paths:
        generated = work_dir / "initial" / f"{slugify(args.case_name)}.bin"
        generated.parent.mkdir(parents=True, exist_ok=True)
        generated.write_bytes(parse_hex_blob(args.raw_hex))
        paths.append(generated)

    collected: list[tuple[Path, bytes, str]] = []
    seen: set[Path] = set()
    for path in paths:
        resolved = path.expanduser().resolve()
        if resolved in seen:
            continue
        if not resolved.is_file():
            raise FileNotFoundError(f"missing RFuzz workload seed: {resolved}")
        data = resolved.read_bytes()
        reject_sfuz_workload(resolved, data)
        collected.append((resolved, data, workload_input_model(resolved, data)))
        seen.add(resolved)
    limit = getattr(args, "limit", 0)
    return collected[:limit] if limit > 0 else collected


def copy_candidate(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def mutate_bytes(parent: bytes, rng: random.Random, round_index: int, max_input_bytes: int = 0) -> tuple[bytes, str]:
    if not parent:
        parent = b"\x00"
    candidate = bytearray(parent)
    operation = round_index % 8
    idx = rng.randrange(len(candidate))

    if operation == 0:
        bit = rng.randrange(8)
        candidate[idx] ^= 1 << bit
        mutation = f"bitflip[{idx}:{bit}]"
    elif operation == 1:
        candidate[idx] = INTERESTING_BYTES[rng.randrange(len(INTERESTING_BYTES))]
        mutation = f"interesting8[{idx}]"
    elif operation == 2:
        delta = rng.randrange(1, 36)
        candidate[idx] = (candidate[idx] + delta) & 0xFF
        mutation = f"arith8+{delta}[{idx}]"
    elif operation == 3:
        delta = rng.randrange(1, 36)
        candidate[idx] = (candidate[idx] - delta) & 0xFF
        mutation = f"arith8-{delta}[{idx}]"
    elif operation == 4 and len(candidate) > 1:
        end = rng.randrange(idx + 1, len(candidate) + 1)
        del candidate[idx:end]
        mutation = f"delete[{idx}:{end}]"
    elif operation == 5:
        block_len = rng.randrange(1, min(16, len(parent)) + 1)
        src = rng.randrange(0, len(parent) - block_len + 1)
        dst = rng.randrange(len(candidate) + 1)
        candidate[dst:dst] = parent[src : src + block_len]
        mutation = f"clone[{src}:{src + block_len}]->{dst}"
    elif operation == 6:
        count = rng.randrange(1, min(8, len(candidate)) + 1)
        for _ in range(count):
            pos = rng.randrange(len(candidate))
            candidate[pos] ^= 1 << rng.randrange(8)
        mutation = f"havoc-bitflipx{count}"
    else:
        candidate[idx] = rng.randrange(256)
        mutation = f"random8[{idx}]"

    if not candidate:
        candidate.append(0)
    if max_input_bytes > 0 and len(candidate) > max_input_bytes:
        del candidate[max_input_bytes:]
        mutation += f";truncate={max_input_bytes}"
    return bytes(candidate), mutation


def mutate_rfuzz_workload(parent: bytes, rng: random.Random, round_index: int, max_input_bytes: int = 0) -> tuple[bytes, str, str]:
    if is_elf_bytes(parent):
        return mutate_linknan_workload(parent, rng, max(1, round_index % 16), max_input_bytes=0)
    child, mutation = mutate_bytes(parent, rng, round_index, max_input_bytes)
    return child, mutation, "binary-workload-raw-bytes"


def invalid_workload_reason(assert_log: Path) -> str:
    return "linknan_workload_loader_assert" if linknan_loader_assertion(assert_log) else ""


def rfuzz_bitmap_total_from_json(bitmap: Path) -> int:
    summary = bitmap.with_suffix(".json")
    if not summary.is_file():
        return 0
    try:
        payload = json.loads(summary.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return 0
    if payload.get("native_backend") != "rfuzz_mux_select_toggle":
        return 0
    try:
        return int(payload.get("total", 0))
    except (TypeError, ValueError):
        return 0


def find_toggle_bitmap(args: Any, case_name: str, input_path: Path, case_dir: Path) -> tuple[bytes, str, int]:
    candidates: list[tuple[Path, str]] = []
    if args.rfuzz_toggle_bitmap:
        candidates.append((args.rfuzz_toggle_bitmap.expanduser(), args.rfuzz_toggle_bitmap_source))
    if args.rfuzz_toggle_bitmap_dir:
        bitmap_dir = args.rfuzz_toggle_bitmap_dir.expanduser()
        for candidate in [
            bitmap_dir / f"{case_name}.bin",
            bitmap_dir / f"{input_path.stem}.bin",
            bitmap_dir / "rfuzz_toggle_bitmap.bin",
        ]:
            candidates.append((candidate, args.rfuzz_toggle_bitmap_source))
    candidates.extend(
        [
            (case_dir / "rfuzz_toggle_bitmap.bin", "vcs-native-abi"),
            (case_dir / "rfuzz_mux_toggle.bin", "vcs-native-abi"),
            (case_dir / f"{case_name}.rfuzz.bin", "vcs-native-abi"),
        ]
    )
    for candidate, source in candidates:
        if candidate.is_file():
            return candidate.read_bytes(), source, rfuzz_bitmap_total_from_json(candidate)
    return b"", "absent", 0


def run_outcome(result: Any, info: Any, infrastructure_error: str) -> str:
    if result.timed_out:
        return "timeout"
    if infrastructure_error:
        return "infrastructure_error"
    if info.bug_triggered:
        return "bug_triggered"
    if info.good_trap_seen:
        return "good_trap"
    if info.max_cycle_exceeded:
        return "max_cycle_reached"
    if info.finish_seen:
        return "finished"
    return "unknown"


def rfuzz_result_meta(rows: list[dict[str, Any]], abi_audit: Any, actual_input_abi: str, cycle_limit: str) -> dict[str, Any]:
    return {
        "fuzzer": "rfuzz",
        "runner_abi": abi_audit.runner_abi,
        "rfuzz_abi_audit": abi_audit.to_dict(),
        "actual_input_abi": actual_input_abi,
        "cycle_limit": cycle_limit,
        "paper_faithful": all(str(row.get("paper_faithful")) == "True" for row in rows) if rows else False,
        "paper_faithful_scope": "linknan-processor-workload",
    }


def run_rfuzz(args: Any, ctx: VcsContext) -> int:
    work_dir = args.work_dir.expanduser().resolve()
    runs_dir = work_dir / "runs"
    logs_dir = work_dir / "logs"
    inputs_dir = work_dir / "inputs"
    corpus_dir = work_dir / "corpus"
    for directory in [runs_dir, logs_dir, inputs_dir, corpus_dir]:
        directory.mkdir(parents=True, exist_ok=True)

    if ctx.cycles is None and args.timeout_sec <= 0:
        raise ValueError("RFuzz --no-cycle-limit runs require --timeout-sec to bound wall-clock time")
    if getattr(args, "require_formal_feedback", False):
        if ctx.cycles is not None:
            raise ValueError("formal RFuzz LinkNan campaigns require --no-cycle-limit")
        if args.timeout_sec < 900:
            raise ValueError("formal RFuzz LinkNan campaigns require --timeout-sec >= 900")
        formal_total_execs = getattr(args, "formal_campaign_total_execs", 0) or args.rfuzz_rounds
        if formal_total_execs < 1000:
            raise ValueError("formal RFuzz LinkNan campaigns require --rfuzz-rounds >= 1000")
        if args.rfuzz_toggle_bitmap_source != "vcs-native-abi":
            raise ValueError("formal RFuzz LinkNan campaigns require VCS-native mux-toggle feedback")
    if not getattr(args, "firrtl_cov", None):
        args.firrtl_cov = "RFuzz.mux-toggle"

    abi_audit = audit_linknan_rfuzz_abi(ctx)
    actual_input_abi = abi_audit.runner_abi
    args.rfuzz_actual_input_abi = actual_input_abi

    initial = collect_initial_workloads(args, ctx, work_dir)
    build_simv_if_needed(args, ctx, work_dir)

    rng = random.Random(args.rfuzz_random_seed)
    coverage = RfuzzCoverageState(args.rfuzz_toggle_total)
    corpus: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    rounds = max(1, args.rfuzz_rounds)
    cycle_limit = "none" if ctx.cycles is None else str(ctx.cycles)

    for round_index in range(1, rounds + 1):
        if round_index <= len(initial):
            source_path, candidate_bytes, input_model = initial[round_index - 1]
            mutation = "initial-workload"
            mutation_model = "none"
            parent_seed = ""
        else:
            if corpus:
                parent = rng.choice(corpus)
                parent_seed = parent["seed"]
                parent_bytes = parent["data"]
                parent_model = parent["input_model"]
            else:
                source_path, parent_bytes, parent_model = initial[(round_index - 1) % len(initial)]
                parent_seed = hashlib.sha256(parent_bytes).hexdigest()[:16]
            candidate_bytes, mutation, mutation_model = mutate_rfuzz_workload(
                parent_bytes,
                rng,
                round_index,
                args.rfuzz_max_input_bytes,
            )
            input_model = parent_model
            source_path = inputs_dir / f"{slugify(args.case_name)}-{round_index:04d}.bin"

        seed_hash = hashlib.sha256(candidate_bytes).hexdigest()[:16]
        input_model = workload_input_model(source_path, candidate_bytes)
        suffix = ".elf" if input_model == "elf-workload" and candidate_bytes.startswith(ELF_MAGIC) else ".bin"
        candidate_path = inputs_dir / f"{slugify(args.case_name)}-{round_index:04d}-{seed_hash}{suffix}"
        copy_candidate(candidate_path, candidate_bytes)

        case_name = f"{slugify(args.case_prefix)}-{round_index:04d}-{seed_hash}"
        result, case_dir, run_log, assert_log = run_vcs_seed(
            seed=candidate_path,
            case_name=case_name,
            runs_dir=runs_dir,
            logs_dir=logs_dir,
            ctx=ctx,
            timeout_sec=args.timeout_sec,
            cov=args.cov,
            simv_args=args.simv_args,
        )
        info = scan_vcs_logs(run_log, assert_log, ctx.cycles)
        invalid_reason = invalid_workload_reason(assert_log)
        invalid_input = bool(invalid_reason)

        infrastructure_error = classify_infrastructure_error(result, info, run_log)

        bitmap, toggle_bitmap_source, bitmap_total = find_toggle_bitmap(args, case_name, candidate_path, case_dir)
        has_native_bitmap = bool(bitmap) and toggle_bitmap_source == "vcs-native-abi"
        rfuzz_total = bitmap_total or args.rfuzz_toggle_total or (len(bitmap) * 8 if bitmap else 0)
        if rfuzz_total and coverage.max_coverage == 0:
            coverage.max_coverage = rfuzz_total
        valid_bool, valid_value = rfuzz_valid_value(args, info)
        valid_known = valid_bool is not None
        coverage_delta = coverage.classify(bitmap, bool(valid_bool)) if bitmap else {
            "new_total": False,
            "new_valid": False,
            "total_covered": coverage.total_covered(),
            "valid_covered": coverage.valid_covered(),
            "growth": 0,
            "total_points": rfuzz_total,
        }

        retention_reasons: list[str] = []
        if not invalid_input and round_index <= len(initial):
            retention_reasons.append("initial_seed")
        if not invalid_input and coverage_delta["new_total"]:
            retention_reasons.append("new_total_coverage")
        if not invalid_input and coverage_delta["new_valid"]:
            retention_reasons.append("new_valid_coverage")
        if info.bug_triggered and not invalid_input:
            retention_reasons.append("design_bug")
        retained = bool(retention_reasons)
        retention_reason = ";".join(retention_reasons) if retention_reasons else ("invalid_input" if invalid_input else "")
        if retained:
            corpus_path = corpus_dir / candidate_path.name
            copy_candidate(corpus_path, candidate_bytes)
            corpus.append(
                {
                    "seed": seed_hash,
                    "path": corpus_path,
                    "data": candidate_bytes,
                    "input_model": input_model,
                    "round": round_index,
                }
            )

        common_coverage = collect_vcs_coverage(args, case_dir, ctx.sim_dir)
        common_backend = common_coverage_backend(common_coverage)
        coverage_backend = "rfuzz_mux_select_vcs_native_abi" if has_native_bitmap else "unavailable"
        covered = popcount_bytes(bitmap) if bitmap else ""
        total = rfuzz_total or ""
        coverage_value = round(100.0 * covered / total, 6) if bitmap and total else ""
        notes = [
            "RFuzz campaign loop executed with normal LinkNan workload file input",
            "No SFUZ structured seed is generated or accepted by this RFuzz path",
            "LinkNan xmake simv-run internally defaults omitted --cycles to +max-cycles=0 (no limit)",
            "Current RFuzz reproduction is intentionally evaluated in LinkNan processor workload mode",
            "The original RFuzz raw pin-stream workload is not used for this processor-verification study",
            abi_audit.raw_pin_stream_reason,
        ]
        notes.extend(abi_audit.notes)
        if ctx.cycles is None:
            notes.append("cycle limit disabled by --no-cycle-limit; wall-clock bounded by --timeout-sec")
        if bitmap and not has_native_bitmap:
            coverage_backend = "rfuzz_mux_select_external_bitmap_diagnostic"
            notes.append("bitmap was supplied, but source is not vcs-native-abi")
        elif not bitmap:
            notes.append("no RFuzz native mux-select bitmap was exported for this run")
        if info.sfuz_expansion_seen:
            notes.append("unexpected SFUZ expansion was seen; this row must be treated as invalid RFuzz data")
        if invalid_input:
            notes.append(f"invalid_input={invalid_reason}; excluded from RFuzz design-bug retention")
        if common_backend != "none":
            notes.append("common_coverage_* is diagnostic/common-backend data, not RFuzz paper-native feedback")

        missing_native_abi = required_native_abi(args, has_native_bitmap, valid_known)
        paper_faithful = not missing_native_abi and actual_input_abi == "linknan-workload-binary-adapter"
        rows.append(
            {
                "fuzzer": "rfuzz",
                "round": round_index,
                "seed": seed_hash,
                "parent_seed": parent_seed,
                "input_path": str(candidate_path),
                "input_size_bytes": len(candidate_bytes),
                "mutation": mutation,
                "mutation_model": mutation_model,
                "runner_abi": abi_audit.runner_abi,
                "requested_input_model": args.rfuzz_input_model,
                "actual_input_abi": actual_input_abi,
                "input_model": input_model,
                "raw_pin_stream_supported": abi_audit.raw_pin_stream_supported,
                "raw_pin_stream_reason": abi_audit.raw_pin_stream_reason,
                "top_input_pins": abi_audit.top_input_pins,
                "fuzzable_input_pins": abi_audit.fuzzable_input_pins,
                "pin_stream_driver_supported": abi_audit.pin_stream_driver_supported,
                "validity_supported": abi_audit.validity_supported,
                "deterministic_reset_model": abi_audit.deterministic_reset_model,
                "sparse_memory_model": abi_audit.sparse_memory_model,
                "cycle_limit": cycle_limit,
                "toggle_bitmap_source": toggle_bitmap_source,
                "valid_source": args.rfuzz_valid_source,
                "valid": valid_value,
                "wall_time_sec": round(result.wall_time_sec, 6),
                "cycles": info.cycles if info.cycles is not None else "",
                "exit_code": result.returncode,
                "vcs_report_seen": info.vcs_report_seen,
                "sfuz_expansion_seen": info.sfuz_expansion_seen,
                "max_cycle_exceeded": info.max_cycle_exceeded,
                "bug_triggered": info.bug_triggered,
                "bug_reasons": info.bug_reasons,
                "invalid_input": invalid_input,
                "invalid_input_reason": invalid_reason,
                "coverage_backend": coverage_backend,
                "coverage_value": coverage_value,
                "covered": covered,
                "total": total,
                "rfuzz_mux_covered": covered,
                "rfuzz_mux_total": total,
                "rfuzz_new_bits": coverage_delta["growth"],
                "new_total_coverage": coverage_delta["new_total"],
                "new_valid_coverage": coverage_delta["new_valid"],
                "total_covered": coverage_delta["total_covered"],
                "valid_covered": coverage_delta["valid_covered"],
                "coverage_growth": coverage_delta["growth"],
                "corpus_size": len(corpus),
                "retained": retained,
                "retention_reason": retention_reason,
                "toggle_bits": bitmap.hex(),
                "common_coverage_backend": common_backend,
                "common_coverage_name": common_coverage.coverage_name,
                "common_coverage_value": common_coverage.coverage_value,
                "common_coverage_source": common_coverage.coverage_source,
                "common_coverage_status": common_coverage.coverage_status,
                "vcs_cpu_time_sec": info.vcs_cpu_time_sec,
                "vcs_sim_time_ps": info.vcs_sim_time_ps,
                "log_path": str(run_log),
                "assert_log_path": str(assert_log),
                "command_log_path": result.command_log_path,
                "case_dir": str(case_dir),
                "case_name": case_name,
                "timed_out": result.timed_out,
                "wall_timeout": wall_timeout(result),
                "design_bug": False if invalid_input else design_bug(info),
                "assertion_failure": False if invalid_input else assertion_failure(info),
                "design_bug_reasons": [] if invalid_input else design_bug_reasons(info),
                "infrastructure_error": infrastructure_error,
                "paper_faithful": paper_faithful,
                "paper_faithful_scope": "linknan-processor-workload",
                "required_native_abi": ";".join(missing_native_abi),
                "notes": append_notes(notes, {"run_outcome": run_outcome(result, info, infrastructure_error)}),
            }
        )
        print(
            f"[{round_index}/{rounds}] rfuzz input={candidate_path.name} "
            f"exit={result.returncode} retained={retained} growth={coverage_delta['growth']} log={run_log}",
            flush=True,
        )
        write_table(
            rows,
            args.output_json or work_dir / "results.json",
            args.output_csv or work_dir / "results.csv",
            RFUZZ_FIELDS,
            rfuzz_result_meta(rows, abi_audit, actual_input_abi, cycle_limit),
        )

    all_paper_faithful = all(str(row.get("paper_faithful")) == "True" for row in rows) if rows else False
    write_table(
        rows,
        args.output_json or work_dir / "results.json",
        args.output_csv or work_dir / "results.csv",
        RFUZZ_FIELDS,
        rfuzz_result_meta(rows, abi_audit, actual_input_abi, cycle_limit),
    )
    if getattr(args, "require_formal_feedback", False) and not all_paper_faithful:
        return 2
    return 0
