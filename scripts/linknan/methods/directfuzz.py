from __future__ import annotations

import csv
import hashlib
import json
import math
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..common import (
    append_notes,
    slugify,
    write_table,
)
from ..config import VcsContext
from ..vcs import build_simv_if_needed, collect_vcs_coverage, common_coverage_backend, run_vcs_seed, scan_vcs_logs


DIRECTFUZZ_FIELDS = [
    "fuzzer",
    "campaign_exec",
    "seed",
    "input_path",
    "input_kind",
    "input_size_bytes",
    "corpus_id",
    "parent_corpus_id",
    "mutation_index",
    "scheduler_queue",
    "retained",
    "retention_reason",
    "target_instance",
    "metadata_source",
    "paper_faithful_scope",
    "wall_time_sec",
    "cycles",
    "exit_code",
    "vcs_report_seen",
    "sfuz_expansion_seen",
    "max_cycle_exceeded",
    "bug_triggered",
    "bug_reasons",
    "vcs_cpu_time_sec",
    "vcs_sim_time_ps",
    "coverage_backend",
    "native_coverage_source",
    "native_coverage_path",
    "target_covered_bits",
    "target_new_bits",
    "new_coverage_bits",
    "accumulated_covered_bits",
    "accumulated_target_covered_bits",
    "distance",
    "energy",
    "new_coverage",
    "target_progress",
    "common_coverage_backend",
    "common_coverage_name",
    "common_coverage_value",
    "common_coverage_source",
    "common_coverage_status",
    "log_path",
    "assert_log_path",
    "command_log_path",
    "case_dir",
    "case_name",
    "timed_out",
    "infrastructure_error",
    "paper_faithful",
    "required_native_abi",
    "notes",
]

DIRECT_METADATA_FIELDS = ["instance_name", "coverage_signal_name", "width", "distance"]
NATIVE_COVERAGE_FIELDS = ["instance_name", "coverage_hex"]
DIRECTFUZZ_INPUT_SUFFIXES = {".bin", ".elf"}
MISSING_PER_INSTANCE_ABI = "directfuzz_per_instance_mux_toggle"
MISSING_NATIVE_EXPORT = "directfuzz_vcs_native_coverage_export"
MISSING_STATIC_METADATA = "directfuzz_static_analysis_instance_distance_metadata"
MISSING_DYNAMIC_COVERAGE = "directfuzz_dynamic_per_testcase_coverage_export"
MISSING_PER_INSTANCE_HIERARCHY_CSV = "directfuzz_per_instance_hierarchy_csv"
PAPER_FAITHFUL_SCOPE = "linknan-processor-workload"


@dataclass(frozen=True)
class InstanceMeta:
    instance: str
    signal: str
    width: int
    distance: int | None

    @property
    def byte_len(self) -> int:
        return math.ceil(self.width / 8)

    @property
    def is_target(self) -> bool:
        return self.distance == 0


@dataclass
class CorpusEntry:
    corpus_id: int
    path: Path
    feedback: dict[str, Any]

    @property
    def covered_target(self) -> bool:
        return int(self.feedback.get("target_covered_bits") or 0) > 0

    @property
    def target_progress(self) -> bool:
        return bool(self.feedback.get("target_progress"))

    @property
    def energy(self) -> float:
        value = self.feedback.get("energy")
        return float(value) if value not in {None, ""} else 0.0


@dataclass
class ScheduledEntry:
    entry: CorpusEntry
    queue_name: str
    use_default_energy: bool = False


class DirectFuzzQueue:
    def __init__(self, escape_interval: int) -> None:
        self.target: list[CorpusEntry] = []
        self.regular: list[CorpusEntry] = []
        self.no_target_progress = 0
        self.escape_interval = max(0, escape_interval)

    def push(self, entry: CorpusEntry) -> None:
        if entry.covered_target:
            self.target.append(entry)
        else:
            self.regular.append(entry)
        if entry.target_progress:
            self.no_target_progress = 0

    def next(self) -> ScheduledEntry | None:
        scheduled: ScheduledEntry | None = None
        if self._should_escape() and self.regular:
            idx = min(range(len(self.regular)), key=lambda pos: self.regular[pos].energy)
            scheduled = ScheduledEntry(self.regular.pop(idx), "regular-escape", True)
        elif self.target:
            scheduled = ScheduledEntry(self.target.pop(0), "target", False)
        elif self.regular:
            scheduled = ScheduledEntry(self.regular.pop(0), "regular", False)

        if scheduled is None:
            return None
        if scheduled.entry.target_progress:
            self.no_target_progress = 0
        else:
            self.no_target_progress += 1
        return scheduled

    def __bool__(self) -> bool:
        return bool(self.target or self.regular)

    def _should_escape(self) -> bool:
        return self.escape_interval > 0 and self.no_target_progress >= self.escape_interval


def parse_distance(value: str) -> int | None:
    text = value.strip()
    if text.lower() in {"undefined", "unreachable", "none", ""}:
        return None
    distance = int(text, 0)
    if distance < 0:
        raise ValueError(f"DirectFuzz distance must be non-negative: {value!r}")
    return None if distance == 256 else distance


def require_csv_fields(path: Path, fieldnames: list[str] | None, required: list[str]) -> None:
    if fieldnames is None:
        raise ValueError(f"{path}: CSV is missing a header")
    missing = [field for field in required if field not in fieldnames]
    if missing:
        raise ValueError(f"{path}: CSV is missing required columns: {', '.join(missing)}")


def load_direct_metadata(path: Path) -> list[InstanceMeta]:
    with path.open(newline="", encoding="utf-8") as input_file:
        reader = csv.DictReader(input_file)
        require_csv_fields(path, reader.fieldnames, DIRECT_METADATA_FIELDS)
        rows: list[InstanceMeta] = []
        seen_instances: set[str] = set()
        for line_no, row in enumerate(reader, 2):
            instance = row["instance_name"].strip()
            signal = row["coverage_signal_name"].strip()
            if not instance:
                raise ValueError(f"{path}:{line_no}: instance_name must be non-empty")
            if not signal:
                raise ValueError(f"{path}:{line_no}: coverage_signal_name must be non-empty")
            if instance in seen_instances:
                raise ValueError(f"{path}:{line_no}: duplicate instance_name {instance!r}")
            seen_instances.add(instance)
            width = int(row["width"], 0)
            if width <= 0:
                raise ValueError(f"{path}:{line_no}: width must be positive")
            rows.append(
                InstanceMeta(
                    instance,
                    signal,
                    width,
                    parse_distance(row["distance"]),
                )
            )
    if not rows:
        raise ValueError(f"{path}: metadata is empty")
    if not any(row.is_target for row in rows):
        raise ValueError(f"{path}: metadata has no target instance at distance 0")
    return rows


def detect_input_kind(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".sfuz":
        return "sfuz"
    if suffix in DIRECTFUZZ_INPUT_SUFFIXES:
        return suffix[1:]
    try:
        data = path.read_bytes()
    except OSError:
        return "unknown"
    if data.startswith(b"\x7fELF"):
        return "elf"
    return "bin"


def validate_direct_input(path: Path) -> None:
    kind = detect_input_kind(path)
    if kind == "sfuz":
        raise ValueError(f"{path}: DirectFuzz LinkNan input must be normal ELF/bin, not .sfuz")
    if kind not in {"elf", "bin"}:
        raise ValueError(f"{path}: DirectFuzz LinkNan input must be normal ELF/bin")


def collect_direct_input_paths(
    seed_args: list[str],
    seed_list: Path | None,
    seed_dir: Path | None,
    work_dir: Path,
    limit: int = 0,
    generate_smoke: bool = True,
) -> list[Path]:
    seeds: list[Path] = []
    for item in seed_args:
        seeds.append(Path(item).expanduser())

    if seed_list:
        base = seed_list.expanduser().resolve().parent
        for raw_line in seed_list.expanduser().read_text(encoding="utf-8").splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            seed = Path(line).expanduser()
            seeds.append(seed if seed.is_absolute() else base / seed)

    if seed_dir:
        seed_dir = seed_dir.expanduser()
        if not seed_dir.is_dir():
            raise FileNotFoundError(f"missing required directory: {seed_dir}")
        for suffix in sorted(DIRECTFUZZ_INPUT_SUFFIXES):
            seeds.extend(sorted(seed_dir.glob(f"*{suffix}")))

    if not seeds and generate_smoke:
        generated = work_dir / "seeds" / "directfuzz-smoke.bin"
        generated.parent.mkdir(parents=True, exist_ok=True)
        generated.write_bytes(bytes.fromhex("73001000"))
        seeds.append(generated)

    resolved: list[Path] = []
    seen: set[Path] = set()
    for seed in seeds:
        path = seed.resolve()
        if not path.is_file():
            raise FileNotFoundError(f"missing required file: {path}")
        validate_direct_input(path)
        if path not in seen:
            resolved.append(path)
            seen.add(path)
    return resolved[:limit] if limit > 0 else resolved


def count_bits_with_width(data: bytes, width: int) -> int:
    full_bytes = width // 8
    tail_bits = width % 8
    count = sum(byte.bit_count() for byte in data[:full_bytes])
    if tail_bits:
        count += (data[full_bytes] & ((1 << tail_bits) - 1)).bit_count()
    return count


def mask_padding_bits(data: bytearray, width: int) -> None:
    tail_bits = width % 8
    if tail_bits:
        data[-1] &= (1 << tail_bits) - 1


def dev_direct_coverage(seed: Path, metadata: list[InstanceMeta], target_instance: str) -> list[bytes]:
    digest = hashlib.sha256(seed.read_bytes() + target_instance.encode("utf-8")).digest()
    coverage: list[bytes] = []
    for idx, meta in enumerate(metadata):
        data = bytearray(meta.byte_len)
        divisor = 3 if meta.is_target else 17 if meta.distance is None else min(13, 4 + meta.distance * 2)
        for bit in range(meta.width):
            h = hashlib.blake2s(
                digest + idx.to_bytes(2, "little") + bit.to_bytes(4, "little") + meta.instance.encode("utf-8"),
                digest_size=4,
            ).digest()
            if int.from_bytes(h, "little") % divisor == 0:
                data[bit // 8] |= 1 << (bit % 8)
        mask_padding_bits(data, meta.width)
        coverage.append(bytes(data))
    return coverage


class DirectCoverageState:
    def __init__(self, metadata: list[InstanceMeta]) -> None:
        self.metadata = metadata
        self.accumulated = [bytearray(meta.byte_len) for meta in metadata]

    def feedback(self, coverage: list[bytes] | None, min_energy: float = 0.0, max_energy: float = 25.0) -> dict[str, Any]:
        if coverage is None:
            return {
                "target_covered_bits": "",
                "target_new_bits": "",
                "new_coverage_bits": "",
                "accumulated_covered_bits": self.accumulated_covered_bits(),
                "accumulated_target_covered_bits": self.accumulated_target_covered_bits(),
                "distance": "",
                "energy": "",
                "new_coverage": "",
                "target_progress": "",
            }
        if len(coverage) != len(self.metadata):
            raise ValueError("coverage length does not match DirectFuzz metadata length")
        for idx, (meta, data) in enumerate(zip(self.metadata, coverage)):
            if len(data) != meta.byte_len:
                raise ValueError(
                    f"coverage for metadata row {idx} instance {meta.instance!r} has {len(data)} bytes, "
                    f"expected {meta.byte_len}"
                )

        target_bits = 0
        reachable_bits = 0
        weighted = 0
        new_cov = False
        target_progress = False
        new_coverage_bits = 0
        target_new_bits = 0
        for idx, (meta, data) in enumerate(zip(self.metadata, coverage)):
            bits = count_bits_with_width(data, meta.width)
            if meta.is_target:
                target_bits += bits
            old = self.accumulated[idx]
            for byte_idx, byte in enumerate(data):
                new_bits = byte & (~old[byte_idx] & 0xFF)
                if new_bits:
                    new_count = new_bits.bit_count()
                    new_coverage_bits += new_count
                    new_cov = True
                    if meta.is_target:
                        target_new_bits += new_count
                        target_progress = True
                old[byte_idx] |= byte
            if meta.distance is not None:
                reachable_bits += bits
                weighted += bits * meta.distance

        distance = None if reachable_bits == 0 else weighted / reachable_bits
        max_distance = max((meta.distance for meta in self.metadata if meta.distance is not None), default=0)
        if distance is None:
            energy = min_energy
        elif max_distance == 0:
            energy = max_energy
        else:
            energy = max_energy - (max_energy - min_energy) * min(max(distance / max_distance, 0.0), 1.0)
        return {
            "target_covered_bits": target_bits,
            "target_new_bits": target_new_bits,
            "new_coverage_bits": new_coverage_bits,
            "accumulated_covered_bits": self.accumulated_covered_bits(),
            "accumulated_target_covered_bits": self.accumulated_target_covered_bits(),
            "distance": "" if distance is None else round(distance, 6),
            "energy": round(energy, 6),
            "new_coverage": new_cov,
            "target_progress": target_progress,
        }

    def accumulated_covered_bits(self) -> int:
        return sum(count_bits_with_width(bytes(data), meta.width) for meta, data in zip(self.metadata, self.accumulated))

    def accumulated_target_covered_bits(self) -> int:
        return sum(
            count_bits_with_width(bytes(data), meta.width)
            for meta, data in zip(self.metadata, self.accumulated)
            if meta.is_target
        )


def normalize_instance_name(name: str) -> str:
    text = name.strip()
    if text == "tb_top.sim":
        return "SimTop"
    if text.startswith("tb_top.sim."):
        return "SimTop." + text[len("tb_top.sim.") :]
    if text == "sim":
        return "SimTop"
    if text.startswith("sim."):
        return "SimTop." + text[len("sim.") :]
    return text


def normalize_module_key(name: str) -> str:
    text = name.strip()
    if text.startswith("module:"):
        return "module:" + text[len("module:") :]
    if text.startswith("coverage_"):
        return "module:" + text[len("coverage_") :]
    return ""


def load_direct_coverage_file(path: Path, metadata: list[InstanceMeta]) -> list[bytes]:
    """Load native DirectFuzz coverage rows in metadata order.

    The CSV schema is intentionally simple for the first LinkNan ABI:
    `instance_name,coverage_hex`. It must contain exactly one row per metadata
    instance. Rows are keyed by instance name and then reordered to metadata
    order. Each `coverage_hex` payload must match the corresponding metadata row
    width after padding bits are masked.
    """
    by_instance: dict[str, bytes] = {}
    by_module: dict[str, bytes] = {}
    metadata_instances = {meta.instance for meta in metadata}
    metadata_modules = {normalize_module_key(meta.signal) for meta in metadata}
    with path.open(newline="", encoding="utf-8") as input_file:
        reader = csv.DictReader(input_file)
        require_csv_fields(path, reader.fieldnames, NATIVE_COVERAGE_FIELDS)
        for line_no, row in enumerate(reader, 2):
            instance = normalize_instance_name(row["instance_name"])
            if not instance:
                raise ValueError(f"{path}:{line_no}: instance_name must be non-empty")
            module_key = normalize_module_key(instance)
            if instance in by_instance or (module_key and module_key in by_module):
                raise ValueError(f"{path}:{line_no}: duplicate coverage row for instance {instance!r}")
            if instance not in metadata_instances and module_key not in metadata_modules:
                continue
            raw_hex = row["coverage_hex"].strip()
            try:
                data = bytes.fromhex(raw_hex)
            except ValueError as exc:
                raise ValueError(f"{path}:{line_no}: invalid coverage_hex for {instance}") from exc
            if module_key:
                by_module[module_key] = data
            else:
                by_instance[instance] = data

    coverage: list[bytes] = []
    for meta in metadata:
        if meta.instance not in by_instance:
            data = by_module.get(normalize_module_key(meta.signal), bytes(meta.byte_len))
        else:
            data = by_instance[meta.instance]
        if len(data) > meta.byte_len:
            data = data[: meta.byte_len]
        if len(data) < meta.byte_len:
            data = data + bytes(meta.byte_len - len(data))
        if len(data) != meta.byte_len:
            raise ValueError(
                f"{path}: instance {meta.instance!r} coverage has {len(data)} bytes, expected {meta.byte_len}"
            )
        mutable = bytearray(data)
        mask_padding_bits(mutable, meta.width)
        coverage.append(bytes(mutable))
    return coverage


def load_direct_aggregate_bitmap(path: Path, metadata: list[InstanceMeta], target_instance: str) -> list[bytes]:
    data = path.read_bytes()
    target_meta = next((meta for meta in metadata if meta.instance == target_instance), None)
    if target_meta is None:
        raise ValueError(f"{path}: target instance {target_instance!r} missing from DirectFuzz metadata")

    coverage: list[bytes] = []
    for meta in metadata:
        row = bytes(meta.byte_len)
        if meta.signal == target_meta.signal:
            row = data[: meta.byte_len]
            if len(row) < meta.byte_len:
                row = row + bytes(meta.byte_len - len(row))
        mutable = bytearray(row)
        mask_padding_bits(mutable, meta.width)
        coverage.append(bytes(mutable))
    return coverage


def resolve_native_coverage_path(args: Any, case_dir: Path, input_path: Path, exec_idx: int) -> Path | None:
    pattern = getattr(args, "native_coverage_pattern", None)
    if pattern:
        return Path(
            pattern.format(
                case_dir=case_dir,
                input=input_path,
                input_stem=input_path.stem,
                exec=exec_idx,
            )
        ).expanduser()
    if args.native_coverage:
        return args.native_coverage.expanduser()

    candidates = [
        case_dir / "directfuzz_coverage.csv",
        case_dir / "directfuzz" / "coverage.csv",
        case_dir / f"{input_path.stem}.directfuzz.csv",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def resolve_native_aggregate_bitmap(case_dir: Path) -> Path | None:
    candidate = case_dir / "directfuzz_coverage.bin"
    return candidate if candidate.is_file() and candidate.stat().st_size > 0 else None


def describe_missing_native_coverage(case_dir: Path) -> str:
    summary_path = case_dir / "directfuzz_coverage.json"
    if not summary_path.is_file():
        return "no DirectFuzz coverage summary json found"
    try:
        payload = json.loads(summary_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        return f"DirectFuzz coverage summary exists but is not valid JSON: {exc}"
    expected_csv = str(payload.get("directfuzz_coverage_file") or "directfuzz_coverage.csv")
    csv_written = payload.get("directfuzz_csv_written", "unknown")
    return f"summary={summary_path}; expected_csv={expected_csv}; directfuzz_csv_written={csv_written}"


def mutate_workload(parent: Path, output: Path, rng: random.Random, budget: int) -> None:
    data = bytearray(parent.read_bytes())
    if not data:
        data.append(0)
    steps = max(1, budget)
    for _ in range(steps):
        op = rng.randrange(6)
        if op == 0:
            idx = rng.randrange(len(data))
            data[idx] ^= 1 << rng.randrange(8)
        elif op == 1:
            idx = rng.randrange(len(data))
            data[idx] = rng.randrange(256)
        elif op == 2 and len(data) > 1:
            del data[rng.randrange(len(data))]
        elif op == 3 and len(data) < 1 << 20:
            idx = rng.randrange(len(data) + 1)
            data[idx:idx] = bytes([rng.randrange(256)])
        elif op == 4 and len(data) > 4:
            start = rng.randrange(len(data))
            end = min(len(data), start + rng.randrange(1, min(16, len(data) - start) + 1))
            chunk = data[start:end]
            insert_at = rng.randrange(len(data) + 1)
            data[insert_at:insert_at] = chunk
        else:
            width = min(4, len(data))
            idx = rng.randrange(len(data) - width + 1)
            value = int.from_bytes(data[idx : idx + width], "little")
            value = (value + rng.choice([-35, -16, -1, 1, 16, 35])) % (1 << (8 * width))
            data[idx : idx + width] = value.to_bytes(width, "little")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(bytes(data))


def mutation_budget(feedback: dict[str, Any], default_energy: bool) -> int:
    if default_energy:
        return 1
    value = feedback.get("energy")
    if value in {None, ""}:
        return 1
    return max(1, min(64, int(round(float(value))) + 1))


def required_native_abi(args: Any, dynamic_native_coverage: bool) -> str:
    missing: list[str] = []
    if args.coverage_backend != "native-file":
        missing.append(MISSING_PER_INSTANCE_ABI)
    elif args.native_coverage_source != "vcs-native-abi":
        missing.append(MISSING_NATIVE_EXPORT)
    if args.metadata_source != "static-analysis":
        missing.append(MISSING_STATIC_METADATA)
    if args.coverage_backend == "native-file" and args.native_coverage and not dynamic_native_coverage:
        missing.append(MISSING_DYNAMIC_COVERAGE)
    missing.append(MISSING_PER_INSTANCE_HIERARCHY_CSV)
    return ";".join(missing)


def paper_faithful_native_file(args: Any) -> bool:
    return False


def direct_notes(args: Any, backend: str, common_backend: str, dynamic_native_coverage: bool) -> list[str]:
    notes = [
        "真实 LinkNan VCS 已运行",
        "DirectFuzz 输入为 LinkNan workload .bin/ELF，不使用 .sfuz",
        "DirectFuzz campaign 由 target-priority/regular corpus queue、distance energy 和 new coverage retention 驱动",
        "使用 --no-cycle-limit 时 xmake 未收到 --cycles；当前 LinkNan 生成的 simv 命令不追加 +max-cycles，外部终止由 --timeout-sec 控制",
    ]
    if args.coverage_backend == "native-file":
        notes.append(f"native coverage backend={backend}; source={args.native_coverage_source}")
        if not dynamic_native_coverage:
            notes.append("当前 native coverage 文件为静态输入，不是每个 testcase 的 VCS 动态导出，不能标记 paper-faithful")
    elif args.coverage_backend == "dev-mock":
        notes.append("coverage/feedback 为 deterministic dev mock，仅用于验证 DirectFuzz 循环管线")
    else:
        notes.append("当前 LinkNan VCS 缺少 DirectFuzz per-instance mux-toggle coverage ABI，stub 不生成 coverage/distance feedback，不进入 feedback-guided mutation queue")
    if common_backend != "none":
        notes.append("common_coverage_* 只用于共同后端诊断，不是 DirectFuzz paper-native feedback")
    return notes


def run_directfuzz(args: Any, ctx: VcsContext) -> int:
    work_dir = args.work_dir.expanduser().resolve()
    runs_dir = work_dir / "runs"
    logs_dir = work_dir / "logs"
    mutations_dir = work_dir / "mutations"
    runs_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    mutations_dir.mkdir(parents=True, exist_ok=True)

    if not getattr(args, "firrtl_cov", None):
        args.firrtl_cov = "DirectFuzz.mux-toggle"

    seeds = collect_direct_input_paths(args.seed, args.seed_list, args.seed_dir, work_dir, args.limit, True)
    metadata = load_direct_metadata(args.metadata.expanduser())
    if not any(row.instance == args.target_instance and row.is_target for row in metadata):
        raise ValueError(f"{args.metadata}: target instance {args.target_instance!r} is not present at distance 0")
    if ctx.cycles is not None:
        raise ValueError("DirectFuzz LinkNan runs must use --no-cycle-limit and external --timeout-sec")

    state = DirectCoverageState(metadata)
    queue = DirectFuzzQueue(args.escape_interval)
    corpus: list[CorpusEntry] = []
    rng = random.Random(args.rng_seed)
    build_simv_if_needed(args, ctx, work_dir)
    rows: list[dict[str, Any]] = []
    campaign_start = time.monotonic()
    exec_budget = args.max_execs if args.max_execs > 0 else len(seeds) + args.mutations

    def run_one(
        *,
        input_path: Path,
        exec_idx: int,
        parent_id: int | str,
        mutation_index: int | str,
        scheduler_queue: str,
        initial_seed: bool,
        default_energy: bool,
    ) -> CorpusEntry | None:
        case_name = f"{slugify(args.case_prefix)}-{exec_idx:04d}-{slugify(input_path.stem)}"
        result, case_dir, run_log, assert_log = run_vcs_seed(
            seed=input_path,
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

        dynamic_native_coverage = not args.native_coverage
        paper_faithful = paper_faithful_native_file(args)
        missing_native_abi = required_native_abi(args, dynamic_native_coverage)
        native_coverage_source = ""
        native_coverage_path = ""
        coverage_notes: list[str] = []
        if args.coverage_backend == "native-file":
            coverage_path = resolve_native_coverage_path(args, case_dir, input_path, exec_idx)
            if coverage_path is None:
                aggregate_path = resolve_native_aggregate_bitmap(case_dir)
                if aggregate_path is None:
                    raise ValueError(
                        "--coverage-backend native-file requires --native-coverage, "
                        "--native-coverage-pattern, or a case-local DirectFuzz coverage CSV; "
                        + describe_missing_native_coverage(case_dir)
                    )
                native_coverage_path = str(aggregate_path)
                feedback = state.feedback(load_direct_aggregate_bitmap(aggregate_path, metadata, args.target_instance))
                backend = "directfuzz_module_type_aggregate_mux_toggle_bitmap"
                coverage_notes.append("case-local DirectFuzz CSV missing; used aggregate bitmap fallback")
            else:
                native_coverage_path = str(coverage_path)
                try:
                    feedback = state.feedback(load_direct_coverage_file(coverage_path, metadata))
                    backend = "directfuzz_per_instance_mux_toggle_file"
                except (UnicodeDecodeError, ValueError) as exc:
                    aggregate_path = resolve_native_aggregate_bitmap(case_dir)
                    if aggregate_path is None:
                        raise
                    native_coverage_path = str(aggregate_path)
                    feedback = state.feedback(load_direct_aggregate_bitmap(aggregate_path, metadata, args.target_instance))
                    backend = "directfuzz_module_type_aggregate_mux_toggle_bitmap"
                    coverage_notes.append(f"per-instance CSV unavailable ({exc}); used aggregate bitmap fallback")
            native_coverage_source = args.native_coverage_source
        elif args.coverage_backend == "dev-mock":
            feedback = state.feedback(dev_direct_coverage(input_path, metadata, args.target_instance))
            backend = "dev_mock_directfuzz_feedback"
        else:
            feedback = state.feedback(None)
            backend = "vcs_log_no_directfuzz_coverage"

        has_direct_feedback = args.coverage_backend in {"native-file", "dev-mock"}
        retained = has_direct_feedback and (initial_seed or bool(feedback.get("new_coverage")))
        if not has_direct_feedback:
            retention_reason = "no-directfuzz-feedback-stub"
        elif initial_seed:
            retention_reason = "initial-seed"
        elif retained:
            retention_reason = "new-coverage"
        else:
            retention_reason = "no-new-coverage"
        entry: CorpusEntry | None = None
        corpus_id: int | str = ""
        if retained:
            corpus_id = len(corpus)
            entry = CorpusEntry(int(corpus_id), input_path, feedback)
            corpus.append(entry)
            queue.push(entry)

        notes = direct_notes(args, backend, common_backend, dynamic_native_coverage)
        notes.extend(coverage_notes)
        if backend == "directfuzz_module_type_aggregate_mux_toggle_bitmap":
            notes.append("module-type aggregate fallback is VCS-native mux-toggle data but not full per-instance hierarchy feedback")
            paper_faithful = False
        if default_energy:
            notes.append("scheduler_escape_default_energy=true")
        if args.timeout_sec <= 0:
            notes.append("未设置外部 --timeout-sec，若 workload 不自然结束可能长期运行")
        rows.append(
            {
                "fuzzer": "directfuzz",
                "campaign_exec": exec_idx,
                "seed": str(input_path),
                "input_path": str(input_path),
                "input_kind": detect_input_kind(input_path),
                "input_size_bytes": input_path.stat().st_size,
                "corpus_id": corpus_id,
                "parent_corpus_id": parent_id,
                "mutation_index": mutation_index,
                "scheduler_queue": scheduler_queue,
                "retained": retained,
                "retention_reason": retention_reason,
                "target_instance": args.target_instance,
                "metadata_source": args.metadata_source,
                "paper_faithful_scope": PAPER_FAITHFUL_SCOPE,
                "wall_time_sec": round(result.wall_time_sec, 6),
                "cycles": info.cycles if info.cycles is not None else "",
                "exit_code": result.returncode,
                "vcs_report_seen": info.vcs_report_seen,
                "sfuz_expansion_seen": info.sfuz_expansion_seen,
                "max_cycle_exceeded": info.max_cycle_exceeded,
                "bug_triggered": info.bug_triggered,
                "bug_reasons": info.bug_reasons,
                "vcs_cpu_time_sec": info.vcs_cpu_time_sec,
                "vcs_sim_time_ps": info.vcs_sim_time_ps,
                "coverage_backend": backend,
                "native_coverage_source": native_coverage_source,
                "native_coverage_path": native_coverage_path,
                **feedback,
                "common_coverage_backend": common_backend,
                "common_coverage_name": common_coverage.coverage_name,
                "common_coverage_value": common_coverage.coverage_value,
                "common_coverage_source": common_coverage.coverage_source,
                "common_coverage_status": common_coverage.coverage_status,
                "log_path": str(run_log),
                "assert_log_path": str(assert_log),
                "command_log_path": result.command_log_path,
                "case_dir": str(case_dir),
                "case_name": case_name,
                "timed_out": result.timed_out,
                "infrastructure_error": infrastructure_error,
                "paper_faithful": paper_faithful,
                "required_native_abi": missing_native_abi,
                "notes": append_notes(
                    notes,
                    {
                        "sfuz_seen": info.sfuz_expansion_seen,
                        "vcs_report": info.vcs_report_seen,
                        "elapsed_campaign_sec": round(time.monotonic() - campaign_start, 6),
                    },
                ),
            }
        )
        return entry

    exec_idx = 0
    for seed in seeds:
        if exec_budget and exec_idx >= exec_budget:
            break
        run_one(
            input_path=seed,
            exec_idx=exec_idx,
            parent_id="",
            mutation_index="seed",
            scheduler_queue="initial",
            initial_seed=True,
            default_energy=False,
        )
        exec_idx += 1

    mutation_idx = 0
    while queue and exec_idx < exec_budget and mutation_idx < args.mutations:
        scheduled = queue.next()
        if scheduled is None:
            break
        budget = mutation_budget(scheduled.entry.feedback, scheduled.use_default_energy)
        mutation_path = mutations_dir / f"mut-{mutation_idx:04d}-parent-{scheduled.entry.corpus_id}.bin"
        mutate_workload(scheduled.entry.path, mutation_path, rng, budget)
        run_one(
            input_path=mutation_path,
            exec_idx=exec_idx,
            parent_id=scheduled.entry.corpus_id,
            mutation_index=mutation_idx,
            scheduler_queue=scheduled.queue_name,
            initial_seed=False,
            default_energy=scheduled.use_default_energy,
        )
        exec_idx += 1
        mutation_idx += 1

    write_table(
        rows,
        args.output_json or work_dir / "results.json",
        args.output_csv or work_dir / "results.csv",
        DIRECTFUZZ_FIELDS,
        {
            "fuzzer": "directfuzz",
            "paper_faithful": all(str(row.get("paper_faithful")) == "True" for row in rows) if rows else False,
            "paper_faithful_scope": PAPER_FAITHFUL_SCOPE,
            "target_instance": args.target_instance,
            "metadata_source": args.metadata_source,
        },
    )
    return 0


def generate_direct_metadata(output: Path, target_instance: str, target_module: str = "") -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        [target_instance, "coverage_target", 16, 0],
        [f"{target_instance}.near", "coverage_near", 24, 1],
        [target_module or "other", "coverage_far", 32, 3],
        ["unreachable", "coverage_dead", 8, 256],
    ]
    with output.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["instance_name", "coverage_signal_name", "width", "distance"])
        writer.writerows(rows)
