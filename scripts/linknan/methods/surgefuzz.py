from __future__ import annotations

import csv
import json
import os
import random
import re
import struct
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..common import append_notes, require_dir, require_file, slugify, write_table
from ..config import VcsContext
from ..surgefuzz_program import Program, ProgramConfig, compile_program
from ..surgefuzz_targets import DEFAULT_TARGET_MANIFEST, SurgeTarget, manifest_table, select_target, target_env
from ..vcs import (
    SFUZZ_FIRRTL_COV_ENV,
    SFUZZ_FIRRTL_COV_OUT_ENV,
    assertion_failure,
    build_simv_if_needed,
    classify_infrastructure_error,
    collect_vcs_coverage,
    common_coverage_backend,
    design_bug,
    design_bug_reasons,
    resolve_tohost_addr,
    run_vcs_seed,
    scan_vcs_logs,
    wall_timeout,
)
from ..workload_mutation import ELF_MAGIC, mutate_linknan_workload


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
    "mutation_operations",
    "surgefuzz_target_id",
    "surgefuzz_target_category",
    "paper_based",
    "extension",
    "rotation_mode",
    "active_target_index",
    "active_target_id",
    "annotation_type",
    "target_signal_or_group",
    "ancestor_selector",
    "ancestor_profile",
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
    "trace_rows",
    "trace_truncated",
    "trace_sample_limit",
    "trace_call_count",
    "trace_target_hit_count",
    "score_column",
    "wall_time_sec",
    "cycles",
    "max_cycle_exceeded",
    "exit_code",
    "vcs_report_seen",
    "sfuz_expansion_seen",
    "good_trap_seen",
    "tohost_exit_seen",
    "tohost_exit_code",
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
    program: Program | None = None
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
    trace_rows: int
    comparison_tier: str
    paper_faithful: bool
    required_native_abi: str
    notes: str


@dataclass(frozen=True)
class RotationTarget:
    id: str
    category: str
    module: str
    instance: str
    signal: str
    annotation: str
    ancestor_selector: str
    ancestor_profile: str
    selected_ancestors: tuple[str, ...]
    distance_selected_ancestors: tuple[str, ...]
    mi_selected_ancestors: tuple[str, ...]
    mi_pruning_applied: bool
    raw: dict[str, Any]


@dataclass
class RotationState:
    targets: list[RotationTarget]
    mode: str
    budget_per_target: int
    stall_threshold: int
    current_index: int = 0
    no_new_by_target: dict[str, int] | None = None

    def __post_init__(self) -> None:
        if self.no_new_by_target is None:
            self.no_new_by_target = {target.id: 0 for target in self.targets}

    def choose(self, exec_count: int) -> tuple[int, RotationTarget]:
        if not self.targets:
            raise ValueError("SurgeFuzz rotation requires at least one target")
        if self.mode == "round-robin":
            self.current_index = exec_count % len(self.targets)
        elif self.mode == "fixed-budget":
            budget = max(1, self.budget_per_target)
            self.current_index = (exec_count // budget) % len(self.targets)
        elif self.mode == "stall-based":
            self.current_index %= len(self.targets)
        else:
            self.current_index = 0
        return self.current_index, self.targets[self.current_index]

    def observe(self, target: RotationTarget, new_coverage: int) -> None:
        if not self.targets or self.mode != "stall-based":
            return
        assert self.no_new_by_target is not None
        if new_coverage > 0:
            self.no_new_by_target[target.id] = 0
            return
        self.no_new_by_target[target.id] = self.no_new_by_target.get(target.id, 0) + 1
        if self.no_new_by_target[target.id] >= max(1, self.stall_threshold):
            self.no_new_by_target[target.id] = 0
            self.current_index = (self.current_index + 1) % len(self.targets)


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


def load_surge_trace(
    path: Path,
    score_column: str,
    target_index: int | None = None,
    target_id: str | None = None,
) -> tuple[list[int], list[tuple[int, ...]]]:
    with path.open(newline="", encoding="utf-8") as input_file:
        reader = csv.DictReader(input_file)
        if reader.fieldnames is None:
            raise ValueError(f"{path}: CSV is missing a header")
        if score_column not in reader.fieldnames:
            raise ValueError(f"{path}: CSV is missing score column {score_column!r}")
        rows = list(reader)
    if target_index is not None and "target_index" in (reader.fieldnames or []):
        rows = [row for row in rows if row.get("target_index") == str(target_index)]
    if target_id and "target_id" in (reader.fieldnames or []):
        rows = [row for row in rows if row.get("target_id") == target_id]
    values = [int(row[score_column], 0) for row in rows]
    dep_cols = [name for name in (reader.fieldnames or []) if name.startswith("dependent_")]
    dependents = []
    for row in rows:
        values_for_row: list[int] = []
        for name in dep_cols:
            raw = row.get(name, "")
            if raw in {None, ""}:
                continue
            values_for_row.append(int(raw, 0))
        dependents.append(tuple(values_for_row))
    return values, dependents


def load_trace_meta(trace: Path) -> dict[str, Any]:
    meta = trace.with_suffix(".meta.json")
    if not meta.is_file():
        return {}
    try:
        payload = json.loads(meta.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def trace_counter_fallback(values: list[int], meta: dict[str, Any]) -> tuple[Any, Any, str]:
    call_count = meta.get("call_count", "")
    target_hit_count = meta.get("target_hit_count", "")
    notes: list[str] = []
    if call_count in {None, ""}:
        call_count = len(values)
        notes.append("trace_call_count_recoverable_from_csv_samples")
    if target_hit_count in {None, ""}:
        target_hit_count = sum(1 for value in values if value != 0)
        notes.append("trace_target_hit_count_recoverable_from_csv_samples")
    return call_count, target_hit_count, "; ".join(notes)


def trace_meta_notes(meta: dict[str, Any]) -> str:
    if not meta:
        return ""
    keys = [
        "samples",
        "call_count",
        "accepted_scope_count",
        "dropped_scope_count",
        "target_hit_count",
        "trace_dropped",
        "target_instance",
        "target_signal",
    ]
    parts = [f"{key}={meta[key]}" for key in keys if key in meta]
    return "trace_meta:" + ",".join(parts) if parts else ""


def resolve_surge_target(args: Any) -> SurgeTarget:
    manifest = getattr(args, "target_manifest", None) or DEFAULT_TARGET_MANIFEST
    target = select_target(Path(manifest).expanduser(), getattr(args, "surge_target", None))
    if getattr(args, "annotation_type", None) is None:
        args.annotation_type = target.annotation
    if getattr(args, "target_signal_or_group", None) is None:
        args.target_signal_or_group = target.signal
    return target


def _string_tuple(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return tuple(item.strip() for item in re.split(r"[,:\s]+", value) if item.strip())
    if isinstance(value, list):
        return tuple(str(item).strip() for item in value if str(item).strip())
    return ()


def load_rotation_targets(path: Path, *, disable_mi: bool = False) -> list[RotationTarget]:
    payload = json.loads(path.expanduser().read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: SurgeFuzz rotation manifest must be a JSON object")
    raw_targets = payload.get("targets", [])
    if not isinstance(raw_targets, list) or not raw_targets:
        raise ValueError(f"{path}: SurgeFuzz rotation manifest requires a non-empty targets list")
    targets: list[RotationTarget] = []
    for index, raw in enumerate(raw_targets):
        if not isinstance(raw, dict):
            raise ValueError(f"{path}: targets[{index}] must be an object")
        mi_selected = _string_tuple(raw.get("mi_selected_ancestors"))
        distance_selected = _string_tuple(raw.get("distance_selected_ancestors"))
        selected = distance_selected if disable_mi and distance_selected else _string_tuple(raw.get("selected_ancestors"))
        if not selected and mi_selected and not disable_mi:
            selected = mi_selected
        if not selected and distance_selected:
            selected = distance_selected
        if not selected:
            raise ValueError(f"{path}: targets[{index}] is missing selected ancestors")
        targets.append(
            RotationTarget(
                id=str(raw.get("id") or f"target_{index}"),
                category=str(raw.get("category") or ""),
                module=str(raw.get("module") or ""),
                instance=str(raw.get("instance") or raw.get("target_instance") or ""),
                signal=str(raw.get("signal") or raw.get("target_signal") or ""),
                annotation=str(raw.get("annotation") or "SURGE_FREQ=1"),
                ancestor_selector="distance" if disable_mi else str(raw.get("ancestor_selector") or "manual"),
                ancestor_profile=str(raw.get("ancestor_profile") or ""),
                selected_ancestors=selected,
                distance_selected_ancestors=distance_selected,
                mi_selected_ancestors=mi_selected,
                mi_pruning_applied=bool(raw.get("mi_pruning_applied")) and not disable_mi,
                raw=dict(raw),
            )
        )
    for target in targets:
        if not target.module or not target.instance or not target.signal:
            raise ValueError(f"{path}: rotation target {target.id!r} requires module, instance, and signal")
    return targets


def write_instrumentation_target_config(path: Path, targets: list[RotationTarget], *, disable_mi: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "mode": "surgefuzz_target_rotation_extension",
        "paper_faithful": False,
        "paper_based": True,
        "extension": "target_rotation",
        "ablation": {"disable_mi": disable_mi},
        "targets": [
            {
                "id": target.id,
                "category": target.category,
                "module": target.module,
                "instance": target.instance,
                "signal": target.signal,
                "annotation": target.annotation,
                "ancestor_selector": target.ancestor_selector,
                "ancestor_profile": target.ancestor_profile,
                "selected_ancestors": list(target.selected_ancestors),
                "distance_selected_ancestors": list(target.distance_selected_ancestors),
                "mi_selected_ancestors": list(target.mi_selected_ancestors),
                "mi_pruning_applied": target.mi_pruning_applied,
            }
            for target in targets
        ],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def temporary_env(overrides: dict[str, str]):
    class _TemporaryEnv:
        def __init__(self, values: dict[str, str]):
            self.values = values
            self.old: dict[str, str | None] = {}

        def __enter__(self):
            for key, value in self.values.items():
                self.old[key] = os.environ.get(key)
                os.environ[key] = value
            return self

        def __exit__(self, _exc_type, _exc, _trace):
            for key, value in self.old.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
            return False

    return _TemporaryEnv(overrides)


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
    data = path.read_bytes()
    with path.open("rb") as input_file:
        magic = input_file.read(4)
    suffix = path.suffix.lower()
    if suffix == ".elf" or magic == b"\x7fELF":
        return WorkloadSeed(path, "linknan-workload-elf", data, "ELF container; mutation preserves ELF metadata")
    if magic == b"SFUZ":
        raise ValueError(
            f"{path}: SurgeFuzz LinkNan campaign expects normal workload .bin/.elf input; "
            ".sfuz is an SFuzz/LinkNan structured seed container and must not be replayed as the SurgeFuzz input"
        )
    return WorkloadSeed(path, "linknan-workload-bin", data, "raw workload bytes")


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
    summary = case_dir / "surgefuzz_trace.json"
    if summary.is_file():
        try:
            payload = json.loads(summary.read_text(encoding="utf-8", errors="replace"))
            trace_raw = str(payload.get("surgefuzz_trace_file") or "")
        except (OSError, json.JSONDecodeError):
            trace_raw = ""
        if trace_raw:
            trace = Path(trace_raw)
            if not trace.is_absolute():
                trace = summary.parent / trace
            if trace.is_file():
                return trace
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
    active_target_index: int | None = None,
    active_target_id: str | None = None,
) -> Feedback:
    trace = find_trace(args, workload, case_dir)
    if trace is not None:
        values, dependents = load_surge_trace(trace, args.score_column, active_target_index, active_target_id)
        meta = load_trace_meta(trace)
        _trace_call_count, _trace_target_hit_count, counter_fallback_note = trace_counter_fallback(values, meta)
        best_score = max(score_series(*annotation, values, args.freq_window), default=0)
        if active_target_index is None:
            ancestor_states = set(dependents)
        else:
            ancestor_states = {(active_target_index, *state) for state in dependents}
        new_states = ancestor_states - global_ancestor_states
        global_ancestor_states.update(ancestor_states)
        trace_source = "dev-mock" if args.trace_is_dev_mock else args.trace_source
        backend, paper_faithful, required_native_abi = trace_backend(trace_source)
        if not values:
            paper_faithful = False
            required_native_abi = REQUIRED_SURGE_NATIVE_ABI
        energy = 1.0 if getattr(args, "disable_power_scheduling", False) else float(max(1, best_score * best_score))
        notes = f"consumed per-cycle SurgeFuzz trace {trace}"
        if active_target_id:
            notes += f"; active_target={active_target_id}"
        meta_note = trace_meta_notes(meta)
        if meta_note:
            notes += f"; {meta_note}"
        elif args.trace_source == "vcs-native-abi":
            notes += "; trace_meta_missing"
        if counter_fallback_note:
            notes += f"; {counter_fallback_note}"
        if not values:
            notes += "; trace has no per-cycle samples, so native SurgeFuzz feedback is not usable yet"
        if not paper_faithful:
            notes += "; trace provenance is not the LinkNan/VCS native ABI"
        if getattr(args, "disable_power_scheduling", False):
            notes += "; ablation=without_power_scheduling"
        return Feedback(
            best_score,
            energy,
            ancestor_states,
            len(new_states),
            backend,
            backend,
            trace_source,
            str(trace),
            len(values),
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
            len(ancestor_states),
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
        0,
        "T0_adapter_stub_loop",
        False,
        REQUIRED_SURGE_NATIVE_ABI,
        "no per-cycle coverage_target/dependent_* trace found; loop used neutral feedback; not paper-faithful",
    )


def select_seed(corpus: list[CorpusEntry], rnd: random.Random, *, disable_power_scheduling: bool = False) -> CorpusEntry:
    weights = [1.0 if disable_power_scheduling else max(1e-6, entry.energy) for entry in corpus]
    entry = rnd.choices(corpus, weights=weights, k=1)[0]
    entry.uses += 1
    return entry


def surgefuzz_mutation_limit(max_execs: int, exec_count: int, configured_mutations: int) -> int:
    if max_execs > 0:
        return max(0, max_execs - exec_count)
    return max(0, configured_mutations)


def program_config_from_args(args: Any) -> ProgramConfig:
    return ProgramConfig(
        initial_seed_block_count=args.initial_seed_block_count,
        initial_seed_instructions_per_block=args.initial_seed_instructions_per_block,
        enable_rv64a=args.enable_rv64a,
        enable_rv64im=args.enable_rv64im,
        enable_insert_memory_access_sequence=args.enable_insert_memory_access_sequence,
        max_operation_count=args.max_operation_count,
        link_address=int(args.link_address, 0) if isinstance(args.link_address, str) else int(args.link_address),
        memory_bytes=args.test_memory_bytes,
        stack_bytes=args.stack_bytes,
        execution_guard_blocks=getattr(args, "artifact_execution_guard_blocks", 12288),
    )


def optional_text(path: Path | None) -> str | None:
    if path is None:
        return None
    return path.expanduser().read_text(encoding="utf-8")


def compile_artifact_workload(
    *,
    program: Program,
    program_config: ProgramConfig,
    generated_dir: Path,
    stem: str,
    args: Any,
) -> tuple[Path, Path, Path, bytes, str]:
    asm_path = generated_dir / f"{stem}.S"
    elf_path = generated_dir / f"{stem}.elf"
    bin_path = generated_dir / f"{stem}.bin"
    try:
        compile_program(
            program,
            output_bin=bin_path,
            output_asm=asm_path,
            output_elf=elf_path,
            config=program_config,
            gcc=args.surgefuzz_riscv_gcc,
            objcopy=args.surgefuzz_objcopy,
            header=optional_text(args.asm_header),
            footer=optional_text(args.asm_footer),
        )
    except subprocess.CalledProcessError as exc:
        output = "\n".join(part for part in [exc.stdout, exc.stderr] if part)
        raise RuntimeError(f"failed to compile SurgeFuzz artifact program {asm_path}: {output}") from exc
    payload = bin_path.read_bytes()
    notes = f"asm={asm_path};elf={elf_path};link_address={program_config.link_address:#x}"
    return bin_path, asm_path, elf_path, payload, notes


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


def mutate_workload_payload(payload: bytes, rnd: random.Random, max_bytes: int) -> tuple[bytes, str, str]:
    child, mutation, model = mutate_linknan_workload(payload, rnd, 1, max_input_bytes=max_bytes)
    if payload.startswith(ELF_MAGIC) and not child.startswith(ELF_MAGIC):
        return payload, "elf-preserve-container-fallback", "workload-preserving-replay"
    return child, mutation, model


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
    active_target_index: int | None = None,
    active_target_id: str | None = None,
) -> tuple[Any, Path, Path, Path, Any, Any, str, str, Feedback]:
    case_dir = runs_dir / case_name
    extra_env = {
        SFUZZ_FIRRTL_COV_ENV: "SurgeFuzz.trace",
        SFUZZ_FIRRTL_COV_OUT_ENV: str(case_dir / "surgefuzz_trace"),
    }
    result, case_dir, run_log, assert_log = run_vcs_seed(
        seed=workload,
        case_name=case_name,
        runs_dir=runs_dir,
        logs_dir=logs_dir,
        ctx=ctx,
        timeout_sec=args.timeout_sec,
        cov=args.cov,
        simv_args=args.simv_args,
        tohost_addr=int(getattr(args, "_surgefuzz_tohost_addr", 0) or 0),
        extra_env=extra_env,
    )
    info = scan_vcs_logs(run_log, assert_log, ctx.cycles)
    common_coverage = collect_vcs_coverage(args, case_dir, ctx.sim_dir)
    common_backend = common_coverage_backend(common_coverage)

    infrastructure_error = classify_infrastructure_error(result, info, run_log)

    feedback = evaluate_feedback(
        args,
        workload,
        case_dir,
        payload,
        annotation,
        global_ancestor_states,
        active_target_index,
        active_target_id,
    )
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
    mutation_operations: list[str] | str = "",
    mutation_backend: str = "",
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
    active_target_index: int | str = "",
    active_target: RotationTarget | None = None,
) -> None:
    target = active_target or getattr(args, "_surge_target", None)
    mutation_ops = ",".join(mutation_operations) if isinstance(mutation_operations, list) else str(mutation_operations)
    input_is_artifact = getattr(args, "input_mode", "workload") == "artifact-program"
    rotation_mode = getattr(args, "rotation_mode", "none")
    extension = "target_rotation" if rotation_mode != "none" else ""
    paper_faithful = feedback.paper_faithful and input_is_artifact and rotation_mode == "none"
    paper_based = rotation_mode != "none"
    annotation_type = target.annotation if isinstance(target, RotationTarget) else args.annotation_type
    signal_or_group = target.signal if isinstance(target, RotationTarget) else args.target_signal_or_group
    ancestor_selector = target.ancestor_selector if isinstance(target, RotationTarget) else getattr(args, "ancestor_selector", "")
    ancestor_profile = target.ancestor_profile if isinstance(target, RotationTarget) else str(getattr(args, "ancestor_profile", "") or "")
    trace_meta = load_trace_meta(Path(feedback.trace_path)) if feedback.trace_path else {}
    trace_truncated = bool(trace_meta.get("trace_dropped", False))
    trace_sample_limit = trace_meta.get("sample_limit", trace_meta.get("max_samples", ""))
    if trace_sample_limit == "" and trace_truncated and feedback.trace_rows:
        trace_sample_limit = feedback.trace_rows
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
            "mutation_backend": mutation_backend or "linknan_workload_bin_byte_mutator",
            "mutation_kind": mutation_kind,
            "mutation_operations": mutation_ops,
            "surgefuzz_target_id": target.id if target is not None else "",
            "surgefuzz_target_category": target.category if target is not None else "",
            "paper_based": paper_based,
            "extension": extension,
            "rotation_mode": rotation_mode,
            "active_target_index": active_target_index,
            "active_target_id": target.id if target is not None else "",
            "annotation_type": annotation_type,
            "target_signal_or_group": signal_or_group,
            "ancestor_selector": ancestor_selector,
            "ancestor_profile": ancestor_profile,
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
            "trace_rows": feedback.trace_rows,
            "trace_truncated": trace_truncated,
            "trace_sample_limit": trace_sample_limit,
            "trace_call_count": trace_meta.get("call_count", ""),
            "trace_target_hit_count": trace_meta.get("target_hit_count", ""),
            "score_column": args.score_column,
            "wall_time_sec": round(result.wall_time_sec, 6),
            "cycles": info.cycles if info.cycles is not None else "",
            "max_cycle_exceeded": info.max_cycle_exceeded,
            "exit_code": result.returncode,
            "vcs_report_seen": info.vcs_report_seen,
            "sfuz_expansion_seen": info.sfuz_expansion_seen,
            "good_trap_seen": info.good_trap_seen,
            "tohost_exit_seen": getattr(info, "tohost_exit_seen", False),
            "tohost_exit_code": getattr(info, "tohost_exit_code", None) if getattr(info, "tohost_exit_code", None) is not None else "",
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
            "paper_faithful": paper_faithful,
            "required_native_abi": feedback.required_native_abi,
            "notes": append_notes(
                feedback.notes,
                extra_notes,
                "" if input_is_artifact else "input_generation=legacy_linknan_workload_adapter_not_artifact_program",
                "paper_based_extension=target_rotation" if extension else "",
                "ablation=without_mi" if getattr(args, "disable_mi", False) else "",
                "ablation=without_power_scheduling" if getattr(args, "disable_power_scheduling", False) else "",
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
    if getattr(args, "require_paper_native", False):
        if args.timeout_sec < 900:
            raise ValueError("formal SurgeFuzz campaigns require --timeout-sec >= 900")
        if args.input_mode != "artifact-program":
            raise ValueError("formal SurgeFuzz campaigns require artifact-program input generation")
        if args.trace_source != "vcs-native-abi" or args.trace_is_dev_mock:
            raise ValueError("formal SurgeFuzz campaigns require VCS-native trace feedback")
        if args.rotation_mode != "none" or getattr(args, "rotation_manifest", None):
            raise ValueError("formal SurgeFuzz paper-native campaigns are single-target; rotation is an extension")
        exec_budget = getattr(args, "formal_campaign_total_execs", 0) or (
            args.max_execs if args.max_execs > 0 else args.initial_seed_count + args.mutations
        )
        if exec_budget < 1000:
            raise ValueError("formal SurgeFuzz campaigns require at least 1000 executions")
    if not getattr(args, "firrtl_cov", None):
        args.firrtl_cov = "SurgeFuzz.trace"

    work_dir = args.work_dir.expanduser().resolve()
    runs_dir = work_dir / "vcs-runs"
    logs_dir = work_dir / "logs"
    generated_dir = work_dir / "generated-workloads"
    runs_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    generated_dir.mkdir(parents=True, exist_ok=True)

    if args.trace_is_dev_mock and args.trace_source == "vcs-native-abi":
        raise ValueError("--trace-is-dev-mock conflicts with --trace-source vcs-native-abi")

    args.target_manifest = Path(args.target_manifest or DEFAULT_TARGET_MANIFEST).expanduser()
    rotation_targets: list[RotationTarget] = []
    rotation_state: RotationState | None = None
    rotation_config_path: Path | None = None
    target: SurgeTarget | RotationTarget
    if getattr(args, "rotation_manifest", None) or getattr(args, "rotation_mode", "none") != "none":
        if getattr(args, "rotation_mode", "none") == "none":
            raise ValueError("--rotation-manifest requires --rotation-mode other than none")
        if not getattr(args, "rotation_manifest", None):
            raise ValueError("--rotation-mode requires --rotation-manifest")
        rotation_manifest = Path(args.rotation_manifest).expanduser().resolve()
        require_file(rotation_manifest)
        rotation_targets = load_rotation_targets(rotation_manifest, disable_mi=getattr(args, "disable_mi", False))
        rotation_state = RotationState(
            rotation_targets,
            args.rotation_mode,
            args.rotation_budget_per_target,
            args.rotation_stall_threshold,
        )
        rotation_config_path = work_dir / "surgefuzz_instrumentation_targets.json"
        write_instrumentation_target_config(rotation_config_path, rotation_targets, disable_mi=getattr(args, "disable_mi", False))
        target = rotation_targets[0]
        args._surge_target = target
        args.annotation_type = args.annotation_type or target.annotation
        args.target_signal_or_group = args.target_signal_or_group or target.signal
        args.ancestor_selector = args.ancestor_selector or target.ancestor_selector
        args.ancestor_profile = args.ancestor_profile or target.ancestor_profile
        args.max_surgefuzz_ancestor_width = args.max_surgefuzz_ancestor_width or 64
        env = {
            "SFUZZ_SURGEFUZZ_TARGET_CONFIG": str(rotation_config_path),
        }
    else:
        target = resolve_surge_target(args)
        args._surge_target = target
        args.ancestor_selector = args.ancestor_selector or target.ancestor_selector
        args.ancestor_profile = args.ancestor_profile or target.ancestor_profile
        args.max_surgefuzz_ancestor_width = args.max_surgefuzz_ancestor_width or target.max_ancestor_width
        args.annotation_type = args.annotation_type or target.annotation
        args.target_signal_or_group = args.target_signal_or_group or target.signal
        env = target_env(target)
        env["SFUZZ_SURGEFUZZ_ANCESTOR_SELECTOR"] = args.ancestor_selector
        env["SFUZZ_SURGEFUZZ_MAX_ANCESTOR_WIDTH"] = str(args.max_surgefuzz_ancestor_width)
        if args.ancestor_profile:
            env["SFUZZ_SURGEFUZZ_ANCESTOR_PROFILE"] = str(Path(args.ancestor_profile).expanduser())

    with temporary_env(env):
        build_simv_if_needed(args, ctx, work_dir)

    global_ancestor_states: set[tuple[int, ...]] = set()
    corpus: list[CorpusEntry] = []
    rows: list[dict[str, Any]] = []
    rnd = random.Random(args.rng_seed)
    _campaign_start = time.monotonic()
    exec_count = 0
    input_mode = getattr(args, "input_mode", "workload")
    args._surgefuzz_tohost_addr = 0

    def checkpoint_results() -> None:
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
                    "The artifact-program mode mutates Program/Block/Instruction objects and emits LinkNan-native "
                    ".bin workloads; workload mode remains a legacy LinkNan .bin/.elf adapter."
                ),
                "cycle_policy": "no --cycles passed by SFuzz; LinkNan xmake simv-run default is +max-cycles=0; external timeout bounds runs",
                "required_native_abi": REQUIRED_SURGE_NATIVE_ABI,
                "input_mode": input_mode,
                "target_manifest": str(args.target_manifest),
                "surgefuzz_targets": manifest_table(args.target_manifest),
                "paper_based": getattr(args, "rotation_mode", "none") != "none",
                "extension": "target_rotation" if getattr(args, "rotation_mode", "none") != "none" else "",
                "rotation": {
                    "mode": getattr(args, "rotation_mode", "none"),
                    "manifest": str(getattr(args, "rotation_manifest", "") or ""),
                    "instrumentation_config": str(rotation_config_path or ""),
                    "target_count": len(rotation_targets),
                    "budget_per_target": getattr(args, "rotation_budget_per_target", ""),
                    "stall_threshold": getattr(args, "rotation_stall_threshold", ""),
                },
                "ablation": {
                    "disable_mi": bool(getattr(args, "disable_mi", False)),
                    "disable_power_scheduling": bool(getattr(args, "disable_power_scheduling", False)),
                },
                "selected_target": {
                    "id": target.id,
                    "category": target.category,
                    "module": target.module,
                    "instance": target.instance,
                    "signal": target.signal,
                    "annotation": args.annotation_type,
                    "ancestor_selector": args.ancestor_selector,
                    "ancestor_profile": str(args.ancestor_profile or ""),
                },
                "paper_faithful": all(str(row.get("paper_faithful")) == "True" for row in rows) if rows else False,
            },
        )

    if input_mode == "artifact-program":
        program_config = program_config_from_args(args)
        max_execs = args.max_execs if args.max_execs > 0 else args.initial_seed_count + args.mutations

        for index in range(args.initial_seed_count):
            if exec_count >= max_execs:
                break
            program = Program.random(rnd, program_config)
            stem = f"surgefuzz-init-{index:04d}"
            workload, asm_path, elf_path, payload, compile_notes = compile_artifact_workload(
                program=program,
                program_config=program_config,
                generated_dir=generated_dir,
                stem=stem,
                args=args,
            )
            active_target_index: int | None = None
            active_target: RotationTarget | None = None
            if rotation_state is not None:
                active_target_index, active_target = rotation_state.choose(exec_count)
                annotation = parse_annotation(active_target.annotation)
            else:
                annotation = parse_annotation(args.annotation_type)
            case_name = f"{slugify(args.case_prefix)}-init-{index:04d}"
            result, case_dir, run_log, assert_log, info, common_coverage, common_backend, infrastructure_error, feedback = run_one(
                args=args,
                ctx=ctx,
                workload=workload,
                payload=payload,
                case_name=case_name,
                runs_dir=runs_dir,
                logs_dir=logs_dir,
                annotation=annotation,
                global_ancestor_states=global_ancestor_states,
                active_target_index=active_target_index,
                active_target_id=active_target.id if active_target is not None else None,
            )
            exec_count += 1
            if rotation_state is not None and active_target is not None:
                rotation_state.observe(active_target, feedback.new_coverage)
            seed_id = len(corpus)
            corpus.append(
                CorpusEntry(
                    seed_id=seed_id,
                    path=workload,
                    payload=payload,
                    input_format="generated-riscv-asm-linknan-bin",
                    parent_seed_id="initial",
                    best_score=feedback.best_score,
                    energy=feedback.energy,
                    program=program,
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
                input_format="generated-riscv-asm-linknan-bin",
                input_size_bytes=len(payload),
                mutation_kind="initial-artifact-program",
                mutation_backend="surgefuzz_artifact_instruction_sequence_mutator",
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
                extra_notes=append_notes(compile_notes, f"asm={asm_path}", f"elf={elf_path}", "artifact_initial_seed=true"),
                active_target_index=active_target_index if active_target_index is not None else "",
                active_target=active_target,
            )
            checkpoint_results()
            print(
                f"[artifact init {index + 1}/{args.initial_seed_count}] exit={result.returncode} "
                f"score={feedback.best_score} new_ancestor={feedback.new_coverage} workload={workload}",
                flush=True,
            )

        mutation_limit = surgefuzz_mutation_limit(args.max_execs, exec_count, args.mutations)
        for round_index in range(mutation_limit):
            if exec_count >= max_execs or not corpus:
                break
            parent = select_seed(corpus, rnd, disable_power_scheduling=getattr(args, "disable_power_scheduling", False))
            if parent.program is None:
                raise RuntimeError("artifact-program corpus entry is missing Program state")
            child_program = parent.program.clone()
            operations = child_program.mutate(rnd, program_config)
            stem = f"surgefuzz-round-{round_index:04d}-parent-{parent.seed_id:04d}"
            workload, asm_path, elf_path, payload, compile_notes = compile_artifact_workload(
                program=child_program,
                program_config=program_config,
                generated_dir=generated_dir,
                stem=stem,
                args=args,
            )
            active_target_index = None
            active_target = None
            if rotation_state is not None:
                active_target_index, active_target = rotation_state.choose(exec_count)
                annotation = parse_annotation(active_target.annotation)
            else:
                annotation = parse_annotation(args.annotation_type)
            case_name = f"{slugify(args.case_prefix)}-round-{round_index:04d}-p{parent.seed_id:04d}"
            result, case_dir, run_log, assert_log, info, common_coverage, common_backend, infrastructure_error, feedback = run_one(
                args=args,
                ctx=ctx,
                workload=workload,
                payload=payload,
                case_name=case_name,
                runs_dir=runs_dir,
                logs_dir=logs_dir,
                annotation=annotation,
                global_ancestor_states=global_ancestor_states,
                active_target_index=active_target_index,
                active_target_id=active_target.id if active_target is not None else None,
            )
            exec_count += 1
            if rotation_state is not None and active_target is not None:
                rotation_state.observe(active_target, feedback.new_coverage)
            keep = feedback.new_coverage > 0
            child_seed_id: int | str = ""
            if keep:
                child_seed_id = len(corpus)
                corpus.append(
                    CorpusEntry(
                        seed_id=child_seed_id,
                        path=workload,
                        payload=payload,
                        input_format="generated-riscv-asm-linknan-bin",
                        parent_seed_id=parent.seed_id,
                        best_score=feedback.best_score,
                        energy=feedback.energy,
                        program=child_program,
                    )
                )
            append_row(
                rows,
                args=args,
                seed=workload,
                seed_id=child_seed_id,
                parent_seed_id=parent.seed_id,
                round_name=round_index,
                case_name=case_name,
                input_format="generated-riscv-asm-linknan-bin",
                input_size_bytes=len(payload),
                mutation_kind="artifact-program-mutation",
                mutation_operations=operations,
                mutation_backend="surgefuzz_artifact_instruction_sequence_mutator",
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
                extra_notes=append_notes(
                    compile_notes,
                    f"asm={asm_path}",
                    f"elf={elf_path}",
                    f"selected_parent={parent.seed_id}",
                    f"kept={keep}",
                ),
                active_target_index=active_target_index if active_target_index is not None else "",
                active_target=active_target,
            )
            checkpoint_results()
            print(
                f"[artifact round {round_index}] parent={parent.seed_id} keep={keep} exit={result.returncode} "
                f"score={feedback.best_score} new_ancestor={feedback.new_coverage} "
                f"global_ancestor={len(global_ancestor_states)} workload={workload}",
                flush=True,
            )
    else:
        workloads = collect_workloads(args, work_dir)
        args._surgefuzz_tohost_addr = resolve_tohost_addr(getattr(args, "tohost_addr", "auto"), workloads)
        max_execs = args.max_execs if args.max_execs > 0 else len(workloads) + args.mutations

        for index, workload in enumerate(workloads):
            if exec_count >= max_execs:
                break
            seed = load_workload_seed(workload)
            active_target_index = None
            active_target = None
            if rotation_state is not None:
                active_target_index, active_target = rotation_state.choose(exec_count)
                annotation = parse_annotation(active_target.annotation)
            else:
                annotation = parse_annotation(args.annotation_type)
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
                active_target_index=active_target_index,
                active_target_id=active_target.id if active_target is not None else None,
            )
            exec_count += 1
            if rotation_state is not None and active_target is not None:
                rotation_state.observe(active_target, feedback.new_coverage)
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
                active_target_index=active_target_index if active_target_index is not None else "",
                active_target=active_target,
            )
            checkpoint_results()
            print(
                f"[bootstrap {index + 1}/{len(workloads)}] exit={result.returncode} "
                f"score={feedback.best_score} new_ancestor={feedback.new_coverage} workload={workload}",
                flush=True,
            )

        mutation_limit = surgefuzz_mutation_limit(args.max_execs, exec_count, args.mutations)
        for round_index in range(mutation_limit):
            if exec_count >= max_execs or not corpus:
                break
            parent = select_seed(corpus, rnd, disable_power_scheduling=getattr(args, "disable_power_scheduling", False))
            child_payload, mutation_kind, mutation_model = mutate_workload_payload(parent.payload, rnd, args.max_input_bytes)
            suffix = ".elf" if child_payload.startswith(ELF_MAGIC) else ".bin"
            child_path = generated_dir / f"surgefuzz-round-{round_index:04d}-parent-{parent.seed_id:04d}{suffix}"
            child_path.write_bytes(child_payload)
            active_target_index = None
            active_target = None
            if rotation_state is not None:
                active_target_index, active_target = rotation_state.choose(exec_count)
                annotation = parse_annotation(active_target.annotation)
            else:
                annotation = parse_annotation(args.annotation_type)
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
                active_target_index=active_target_index,
                active_target_id=active_target.id if active_target is not None else None,
            )
            exec_count += 1
            if rotation_state is not None and active_target is not None:
                rotation_state.observe(active_target, feedback.new_coverage)
            keep = feedback.new_coverage > 0
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
                mutation_backend=mutation_model,
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
                active_target_index=active_target_index if active_target_index is not None else "",
                active_target=active_target,
            )
            checkpoint_results()
            print(
                f"[round {round_index}] parent={parent.seed_id} keep={keep} exit={result.returncode} "
                f"score={feedback.best_score} new_ancestor={feedback.new_coverage} "
                f"global_ancestor={len(global_ancestor_states)} workload={child_path}",
                flush=True,
            )

    all_paper_faithful = all(str(row.get("paper_faithful")) == "True" for row in rows) if rows else False
    checkpoint_results()
    if getattr(args, "require_paper_native", False) and not all_paper_faithful:
        return 2
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
