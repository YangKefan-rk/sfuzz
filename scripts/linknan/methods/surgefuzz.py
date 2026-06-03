from __future__ import annotations

import csv
import random
import re
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..common import append_notes, require_dir, require_file, slugify, write_table
from ..config import VcsContext
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


REQUIRED_SURGE_NATIVE_ABI = "surgefuzz_per_cycle_score_and_ancestor_coverage"
RUNNER_ABI = "linknan-workload-simv-run"
DEFAULT_SMOKE_BIN = bytes.fromhex("73001000")
PT_LOAD = 1

SURGEFUZZ_FIELDS = [
    "fuzzer",
    "seed",
    "seed_id",
    "parent_seed_id",
    "round",
    "case_name",
    "comparison_tier",
    "runner_abi",
    "input_format",
    "input_size_bytes",
    "mutation_backend",
    "mutation_kind",
    "annotation_type",
    "target_signal_or_group",
    "best_score",
    "energy",
    "ancestor_coverage_bits",
    "new_coverage",
    "global_ancestor_coverage",
    "corpus_size",
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
    "wall_timeout",
    "design_bug",
    "assertion_failure",
    "design_bug_reasons",
    "infrastructure_error",
    "paper_faithful",
    "required_native_abi",
    "notes",
    "coverage_total",
    "coverage_covered",
    "coverage_acc",
]


@dataclass
class WorkloadSeed:
    path: Path
    input_format: str
    payload: bytes
    source_notes: str


@dataclass
class CorpusEntry:
    seed_id: int
    path: Path
    payload: bytes
    input_format: str
    parent_seed_id: int | str
    best_score: int
    energy: float
    uses: int = 0


@dataclass
class Feedback:
    best_score: int
    energy: float
    ancestor_states: set[tuple[int, ...]]
    new_coverage: int
    coverage_backend: str
    score_backend: str
    trace_source: str
    trace_path: str
    comparison_tier: str
    paper_faithful: bool
    required_native_abi: str
    notes: str


@dataclass(frozen=True)
class ElfSegment:
    load_addr: int
    file_offset: int
    file_size: int
    mem_size: int


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


def select_struct_format(endianness: int, payload: str) -> str:
    if endianness == 1:
        return "<" + payload
    if endianness == 2:
        return ">" + payload
    raise ValueError(f"unsupported ELF endianness tag: {endianness}")


def flatten_elf_load_segments(path: Path) -> bytes:
    with path.open("rb") as input_file:
        ident = input_file.read(16)
        if len(ident) != 16 or ident[:4] != b"\x7fELF":
            raise ValueError(f"file is not an ELF binary: {path}")
        elf_class = ident[4]
        endianness = ident[5]
        if elf_class == 1:
            header_format = select_struct_format(endianness, "HHIIIIIHHHHHH")
            program_header_format = select_struct_format(endianness, "IIIIIIII")
            is_64_bit = False
        elif elf_class == 2:
            header_format = select_struct_format(endianness, "HHIQQQIHHHHHH")
            program_header_format = select_struct_format(endianness, "IIQQQQQQ")
            is_64_bit = True
        else:
            raise ValueError(f"unsupported ELF class {elf_class} in {path}")

        header = input_file.read(struct.calcsize(header_format))
        fields = struct.unpack(header_format, header)
        e_phoff = fields[4]
        e_phentsize = fields[8]
        e_phnum = fields[9]
        expected_phdr_size = struct.calcsize(program_header_format)
        segments: list[ElfSegment] = []
        for index in range(e_phnum):
            input_file.seek(e_phoff + index * e_phentsize)
            raw_header = input_file.read(e_phentsize)
            if len(raw_header) != e_phentsize:
                raise ValueError(f"failed to read ELF program header {index} from {path}")
            program_header = raw_header[:expected_phdr_size]
            if is_64_bit:
                p_type, _flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, _align = struct.unpack(
                    program_header_format, program_header
                )
            else:
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, _flags, _align = struct.unpack(
                    program_header_format, program_header
                )
            if p_type == PT_LOAD and p_memsz:
                load_addr = p_paddr if p_paddr != 0 else p_vaddr
                segments.append(ElfSegment(load_addr, p_offset, p_filesz, p_memsz))

        if not segments:
            raise ValueError(f"ELF file contains no loadable PT_LOAD segments: {path}")

        segments.sort(key=lambda segment: segment.load_addr)
        base = segments[0].load_addr
        size = max(segment.load_addr + segment.mem_size for segment in segments) - base
        payload = bytearray(size)
        for segment in segments:
            input_file.seek(segment.file_offset)
            data = input_file.read(segment.file_size)
            start = segment.load_addr - base
            payload[start : start + len(data)] = data
        return bytes(payload)


def _read_exact(data: bytes, cursor: int, size: int) -> tuple[bytes, int]:
    end = cursor + size
    if end > len(data):
        raise ValueError("short SFUZ file")
    return data[cursor:end], end


def _read_u16(data: bytes, cursor: int) -> tuple[int, int]:
    raw, cursor = _read_exact(data, cursor, 2)
    return struct.unpack("<H", raw)[0], cursor


def _read_u32(data: bytes, cursor: int) -> tuple[int, int]:
    raw, cursor = _read_exact(data, cursor, 4)
    return struct.unpack("<I", raw)[0], cursor


def _read_blob(data: bytes, cursor: int) -> tuple[bytes, int]:
    size, cursor = _read_u32(data, cursor)
    return _read_exact(data, cursor, size)


def extract_sfuz_core0(path: Path) -> bytes:
    data = path.read_bytes()
    if not data.startswith(b"SFUZ"):
        raise ValueError(f"{path}: not an SFUZ container")
    cursor = 4
    version, cursor = _read_u16(data, cursor)
    if version != 1:
        raise ValueError(f"{path}: unsupported SFUZ version {version}")
    _reserved, cursor = _read_u16(data, cursor)
    core0, _cursor = _read_blob(data, cursor)
    return core0


def load_workload_seed(path: Path) -> WorkloadSeed:
    with path.open("rb") as input_file:
        magic = input_file.read(4)
    suffix = path.suffix.lower()
    if suffix == ".elf" or magic == b"\x7fELF":
        return WorkloadSeed(path, "linknan-workload-elf", flatten_elf_load_segments(path), "ELF PT_LOAD payload")
    if magic == b"SFUZ":
        raise ValueError(
            f"{path}: SurgeFuzz LinkNan campaign expects normal workload .bin/.elf input; "
            ".sfuz is an SFuzz/LinkNan structured seed container and must not be replayed as the SurgeFuzz input"
        )
    return WorkloadSeed(path, "linknan-workload-bin", path.read_bytes(), "raw workload bytes")


def collect_workloads(args: Any, work_dir: Path) -> list[Path]:
    workloads: list[Path] = []
    for attr in ("workload", "seed"):
        for item in getattr(args, attr, []) or []:
            workloads.append(Path(item).expanduser())

    for attr in ("workload_list", "seed_list"):
        list_path = getattr(args, attr, None)
        if not list_path:
            continue
        list_path = list_path.expanduser()
        base = list_path.resolve().parent
        for raw_line in list_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            path = Path(line).expanduser()
            workloads.append(path if path.is_absolute() else base / path)

    for attr in ("workload_dir", "seed_dir"):
        directory = getattr(args, attr, None)
        if not directory:
            continue
        directory = directory.expanduser()
        require_dir(directory)
        for pattern in ("*.bin", "*.elf"):
            workloads.extend(sorted(directory.glob(pattern)))

    if not workloads:
        generated = work_dir / "seeds" / "surgefuzz-smoke.bin"
        generated.parent.mkdir(parents=True, exist_ok=True)
        generated.write_bytes(DEFAULT_SMOKE_BIN)
        workloads.append(generated)

    resolved: list[Path] = []
    seen: set[Path] = set()
    for workload in workloads:
        path = workload.resolve()
        require_file(path)
        if path not in seen:
            resolved.append(path)
            seen.add(path)
    limit = getattr(args, "limit", 0) or 0
    return resolved[:limit] if limit > 0 else resolved


def trace_backend(trace_source: str) -> tuple[str, bool, str]:
    if trace_source == "vcs-native-abi":
        return "surgefuzz_vcs_native_abi_trace", True, ""
    if trace_source == "dev-mock":
        return "dev_mock_score_trace", False, REQUIRED_SURGE_NATIVE_ABI
    return "surgefuzz_offline_trace_csv", False, REQUIRED_SURGE_NATIVE_ABI


def find_native_trace(case_dir: Path) -> Path | None:
    candidates = [
        case_dir / "surgefuzz_trace.csv",
        case_dir / "surgefuzz_per_cycle.csv",
        case_dir / "surgefuzz_feedback.csv",
    ]
    if case_dir.exists():
        candidates.extend(sorted(case_dir.rglob("surgefuzz*trace*.csv")))
        candidates.extend(sorted(case_dir.rglob("surgefuzz*feedback*.csv")))
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def find_trace(args: Any, workload: Path, case_dir: Path) -> Path | None:
    if args.score_trace_dir:
        trace_dir = args.score_trace_dir.expanduser()
        for candidate in (trace_dir / f"{workload.stem}.csv", trace_dir / f"{case_dir.name}.csv"):
            if candidate.is_file():
                return candidate
    if args.trace_source == "vcs-native-abi":
        return find_native_trace(case_dir)
    return None


def synthesize_stub_feedback(payload: bytes, annotation: tuple[str, bool, str], window: int) -> tuple[int, set[tuple[int, ...]]]:
    values: list[int] = []
    dependents: list[tuple[int, ...]] = []
    data = payload or DEFAULT_SMOKE_BIN
    for cycle, byte in enumerate(data[:1024]):
        nxt = data[(cycle + 1) % len(data)]
        values.append((byte >> (cycle % 8)) & 1)
        dependents.append((byte & 0x0F, (byte >> 4) & 0x0F, nxt & 0x03))
    return max(score_series(*annotation, values, window), default=0), set(dependents)


def evaluate_feedback(
    args: Any,
    workload: Path,
    case_dir: Path,
    payload: bytes,
    annotation: tuple[str, bool, str],
    global_ancestor_states: set[tuple[int, ...]],
) -> Feedback:
    trace = find_trace(args, workload, case_dir)
    if trace is not None:
        values, dependents = load_surge_trace(trace, args.score_column)
        best_score = max(score_series(*annotation, values, args.freq_window), default=0)
        ancestor_states = set(dependents)
        new_states = ancestor_states - global_ancestor_states
        global_ancestor_states.update(ancestor_states)
        trace_source = "dev-mock" if args.trace_is_dev_mock else args.trace_source
        backend, paper_faithful, required_native_abi = trace_backend(trace_source)
        notes = f"consumed per-cycle SurgeFuzz trace {trace}"
        if not paper_faithful:
            notes += "; trace provenance is not the LinkNan/VCS native ABI"
        return Feedback(
            best_score,
            float(max(1, best_score * best_score)),
            ancestor_states,
            len(new_states),
            backend,
            backend,
            trace_source,
            str(trace),
            "T2_processor_workload_native_feedback" if paper_faithful else "T0_trace_loop",
            paper_faithful,
            required_native_abi,
            notes,
        )

    if args.trace_source == "dev-mock" or args.trace_is_dev_mock:
        best_score, ancestor_states = synthesize_stub_feedback(payload, annotation, args.freq_window)
        new_states = ancestor_states - global_ancestor_states
        global_ancestor_states.update(ancestor_states)
        return Feedback(
            best_score,
            float(max(1, best_score * best_score)),
            ancestor_states,
            len(new_states),
            "surgefuzz_adapter_stub_dev_mock",
            "surgefuzz_adapter_stub_dev_mock",
            "adapter-stub-dev-mock",
            "",
            "T0_adapter_stub_loop",
            False,
            REQUIRED_SURGE_NATIVE_ABI,
            "adapter synthesized score/ancestor coverage from workload bytes; not paper-faithful",
        )

    return Feedback(
        0,
        1.0,
        set(),
        0,
        "surgefuzz_adapter_stub_unavailable",
        "unavailable",
        "no-trace",
        "",
        "T0_adapter_stub_loop",
        False,
        REQUIRED_SURGE_NATIVE_ABI,
        "no per-cycle coverage_target/dependent_* trace found; loop used neutral feedback; not paper-faithful",
    )


def select_seed(corpus: list[CorpusEntry], rnd: random.Random) -> CorpusEntry:
    weights = [max(1.0, entry.energy) / (1 + entry.uses) for entry in corpus]
    entry = rnd.choices(corpus, weights=weights, k=1)[0]
    entry.uses += 1
    return entry


def mutate_payload(payload: bytes, rnd: random.Random, max_bytes: int) -> tuple[bytes, str]:
    data = bytearray(payload or DEFAULT_SMOKE_BIN)
    operation = rnd.choice(["flip-bit", "overwrite-word", "insert-word", "delete-word"])
    if operation == "flip-bit" and data:
        index = rnd.randrange(len(data))
        data[index] ^= 1 << rnd.randrange(8)
    elif operation == "overwrite-word":
        offset = rnd.randrange(max(1, len(data)))
        replacement = rnd.randbytes(4)
        data[offset : min(len(data), offset + 4)] = replacement[: max(1, min(4, len(data) - offset))]
    elif operation == "insert-word":
        offset = rnd.randrange(len(data) + 1)
        data[offset:offset] = rnd.randbytes(4)
    elif operation == "delete-word" and len(data) > 4:
        offset = rnd.randrange(len(data) - 3)
        del data[offset : offset + 4]
    else:
        data.extend(rnd.randbytes(4))
        operation = "append-word"
    if max_bytes > 0 and len(data) > max_bytes:
        del data[max_bytes:]
        operation += "-truncated"
    return bytes(data), operation


def run_one(
    *,
    args: Any,
    ctx: VcsContext,
    workload: Path,
    payload: bytes,
    case_name: str,
    runs_dir: Path,
    logs_dir: Path,
    annotation: tuple[str, bool, str],
    global_ancestor_states: set[tuple[int, ...]],
) -> tuple[Any, Path, Path, Path, Any, Any, str, str, Feedback]:
    result, case_dir, run_log, assert_log = run_vcs_seed(
        seed=workload,
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

    infrastructure_error = classify_infrastructure_error(result, info, run_log)

    feedback = evaluate_feedback(args, workload, case_dir, payload, annotation, global_ancestor_states)
    return result, case_dir, run_log, assert_log, info, common_coverage, common_backend, infrastructure_error, feedback


def append_row(
    rows: list[dict[str, Any]],
    *,
    args: Any,
    seed: Path,
    seed_id: int | str,
    parent_seed_id: int | str,
    round_name: int | str,
    case_name: str,
    input_format: str,
    input_size_bytes: int,
    mutation_kind: str,
    result: Any,
    case_dir: Path,
    run_log: Path,
    assert_log: Path,
    info: Any,
    common_coverage: Any,
    common_backend: str,
    infrastructure_error: str,
    feedback: Feedback,
    global_ancestor_states: set[tuple[int, ...]],
    corpus_size: int,
    extra_notes: str = "",
) -> None:
    rows.append(
        {
            "fuzzer": "surgefuzz",
            "seed": str(seed),
            "seed_id": seed_id,
            "parent_seed_id": parent_seed_id,
            "round": round_name,
            "case_name": case_name,
            "comparison_tier": feedback.comparison_tier,
            "runner_abi": RUNNER_ABI,
            "input_format": input_format,
            "input_size_bytes": input_size_bytes,
            "mutation_backend": "linknan_workload_bin_byte_mutator",
            "mutation_kind": mutation_kind,
            "annotation_type": args.annotation_type,
            "target_signal_or_group": args.target_signal_or_group,
            "best_score": feedback.best_score,
            "energy": feedback.energy,
            "ancestor_coverage_bits": len(feedback.ancestor_states),
            "new_coverage": feedback.new_coverage,
            "global_ancestor_coverage": len(global_ancestor_states),
            "corpus_size": corpus_size,
            "coverage_backend": feedback.coverage_backend,
            "common_coverage_backend": common_backend,
            "common_coverage_name": common_coverage.coverage_name,
            "common_coverage_value": common_coverage.coverage_value,
            "common_coverage_source": common_coverage.coverage_source,
            "common_coverage_status": common_coverage.coverage_status,
            "score_backend": feedback.score_backend,
            "trace_source": feedback.trace_source,
            "trace_path": feedback.trace_path,
            "score_column": args.score_column,
            "wall_time_sec": round(result.wall_time_sec, 6),
            "cycles": info.cycles if info.cycles is not None else "",
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
            "wall_timeout": wall_timeout(result),
            "design_bug": design_bug(info),
            "assertion_failure": assertion_failure(info),
            "design_bug_reasons": design_bug_reasons(info),
            "infrastructure_error": infrastructure_error,
            "paper_faithful": feedback.paper_faithful,
            "required_native_abi": feedback.required_native_abi,
            "notes": append_notes(
                feedback.notes,
                extra_notes,
                {
                    "cycle_policy": "natural-end-or-timeout",
                    "xmake_default_max_cycles": "0_when_--cycles_omitted",
                    "sfuz_seen": info.sfuz_expansion_seen,
                    "vcs_report": info.vcs_report_seen,
                },
            ),
            "coverage_total": "",
            "coverage_covered": "",
            "coverage_acc": "",
        }
    )


def run_surgefuzz(args: Any, ctx: VcsContext) -> int:
    if getattr(args, "cycles", None) is not None:
        raise ValueError(
            "SurgeFuzz LinkNan experiments must not set --cycles; use --no-cycle-limit "
            "with --timeout-sec so VCS runs until natural finish or the external timeout"
        )
    if ctx.cycles is not None:
        raise ValueError(
            "SurgeFuzz LinkNan experiments must use natural workload end or external timeout; "
            "pass --no-cycle-limit and set --timeout-sec instead of --cycles"
        )
    if args.timeout_sec <= 0:
        raise ValueError("SurgeFuzz LinkNan loop requires --timeout-sec to bound natural-end VCS runs")

    work_dir = args.work_dir.expanduser().resolve()
    runs_dir = work_dir / "vcs-runs"
    logs_dir = work_dir / "logs"
    generated_dir = work_dir / "generated-workloads"
    runs_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    generated_dir.mkdir(parents=True, exist_ok=True)

    workloads = collect_workloads(args, work_dir)
    if args.trace_is_dev_mock and args.trace_source == "vcs-native-abi":
        raise ValueError("--trace-is-dev-mock conflicts with --trace-source vcs-native-abi")
    build_simv_if_needed(args, ctx, work_dir)

    annotation = parse_annotation(args.annotation_type)
    global_ancestor_states: set[tuple[int, ...]] = set()
    corpus: list[CorpusEntry] = []
    rows: list[dict[str, Any]] = []
    rnd = random.Random(args.rng_seed)
    _campaign_start = time.monotonic()
    exec_count = 0
    max_execs = args.max_execs if args.max_execs > 0 else len(workloads) + args.mutations

    for index, workload in enumerate(workloads):
        if exec_count >= max_execs:
            break
        seed = load_workload_seed(workload)
        case_name = f"{slugify(args.case_prefix)}-bootstrap-{index:03d}-{slugify(workload.stem)}"
        result, case_dir, run_log, assert_log, info, common_coverage, common_backend, infrastructure_error, feedback = run_one(
            args=args,
            ctx=ctx,
            workload=workload,
            payload=seed.payload,
            case_name=case_name,
            runs_dir=runs_dir,
            logs_dir=logs_dir,
            annotation=annotation,
            global_ancestor_states=global_ancestor_states,
        )
        exec_count += 1
        seed_id = len(corpus)
        corpus.append(
            CorpusEntry(
                seed_id=seed_id,
                path=workload,
                payload=seed.payload,
                input_format=seed.input_format,
                parent_seed_id="initial",
                best_score=feedback.best_score,
                energy=feedback.energy,
            )
        )
        append_row(
            rows,
            args=args,
            seed=workload,
            seed_id=seed_id,
            parent_seed_id="initial",
            round_name="bootstrap",
            case_name=case_name,
            input_format=seed.input_format,
            input_size_bytes=len(seed.payload),
            mutation_kind="initial-workload",
            result=result,
            case_dir=case_dir,
            run_log=run_log,
            assert_log=assert_log,
            info=info,
            common_coverage=common_coverage,
            common_backend=common_backend,
            infrastructure_error=infrastructure_error,
            feedback=feedback,
            global_ancestor_states=global_ancestor_states,
            corpus_size=len(corpus),
            extra_notes=seed.source_notes,
        )
        print(
            f"[bootstrap {index + 1}/{len(workloads)}] exit={result.returncode} "
            f"score={feedback.best_score} new_ancestor={feedback.new_coverage} workload={workload}",
            flush=True,
        )

    for round_index in range(args.mutations):
        if exec_count >= max_execs or not corpus:
            break
        parent = select_seed(corpus, rnd)
        child_payload, mutation_kind = mutate_payload(parent.payload, rnd, args.max_input_bytes)
        child_path = generated_dir / f"surgefuzz-round-{round_index:04d}-parent-{parent.seed_id:04d}.bin"
        child_path.write_bytes(child_payload)
        case_name = f"{slugify(args.case_prefix)}-round-{round_index:04d}-p{parent.seed_id:04d}"
        result, case_dir, run_log, assert_log, info, common_coverage, common_backend, infrastructure_error, feedback = run_one(
            args=args,
            ctx=ctx,
            workload=child_path,
            payload=child_payload,
            case_name=case_name,
            runs_dir=runs_dir,
            logs_dir=logs_dir,
            annotation=annotation,
            global_ancestor_states=global_ancestor_states,
        )
        exec_count += 1
        keep = feedback.new_coverage > 0 or feedback.best_score > parent.best_score
        child_seed_id: int | str = ""
        if keep:
            child_seed_id = len(corpus)
            corpus.append(
                CorpusEntry(
                    seed_id=child_seed_id,
                    path=child_path,
                    payload=child_payload,
                    input_format="generated-linknan-workload-bin",
                    parent_seed_id=parent.seed_id,
                    best_score=feedback.best_score,
                    energy=feedback.energy,
                )
            )
        append_row(
            rows,
            args=args,
            seed=child_path,
            seed_id=child_seed_id,
            parent_seed_id=parent.seed_id,
            round_name=round_index,
            case_name=case_name,
            input_format="generated-linknan-workload-bin",
            input_size_bytes=len(child_payload),
            mutation_kind=mutation_kind,
            result=result,
            case_dir=case_dir,
            run_log=run_log,
            assert_log=assert_log,
            info=info,
            common_coverage=common_coverage,
            common_backend=common_backend,
            infrastructure_error=infrastructure_error,
            feedback=feedback,
            global_ancestor_states=global_ancestor_states,
            corpus_size=len(corpus),
            extra_notes=f"selected_parent={parent.seed_id};kept={keep}",
        )
        print(
            f"[round {round_index}] parent={parent.seed_id} keep={keep} exit={result.returncode} "
            f"score={feedback.best_score} new_ancestor={feedback.new_coverage} "
            f"global_ancestor={len(global_ancestor_states)} workload={child_path}",
            flush=True,
        )

    write_table(
        rows,
        args.output_json or work_dir / "surgefuzz_results.json",
        args.output_csv or work_dir / "surgefuzz_results.csv",
        SURGEFUZZ_FIELDS,
        {
            "fuzzer": "surgefuzz",
            "input_contract": (
                "Paper/artifact SurgeFuzz generates RISC-V instruction programs, compiles them to a simulator "
                "workload, and feeds back per-cycle annotated-signal score plus ancestor-register coverage. "
                "This LinkNan adapter runs normal workload .bin/.elf inputs and rejects .sfuz replay containers; "
                "generated mutations are emitted as .bin workloads."
            ),
            "cycle_policy": "no --cycles passed by SFuzz; LinkNan xmake simv-run default is +max-cycles=0; external timeout bounds runs",
            "required_native_abi": REQUIRED_SURGE_NATIVE_ABI,
        },
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
