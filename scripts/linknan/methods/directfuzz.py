from __future__ import annotations

import csv
import hashlib
import math
from dataclasses import dataclass
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


DIRECTFUZZ_FIELDS = [
    "fuzzer",
    "seed",
    "target_instance",
    "wall_time_sec",
    "cycles",
    "exit_code",
    "coverage_backend",
    "target_covered_bits",
    "distance",
    "energy",
    "new_coverage",
    "target_progress",
    "log_path",
    "paper_faithful",
    "required_native_abi",
    "notes",
]


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


def parse_distance(value: str) -> int | None:
    text = value.strip()
    if text.lower() in {"undefined", "unreachable", "none", ""}:
        return None
    distance = int(text, 0)
    return None if distance == 256 else distance


def load_direct_metadata(path: Path) -> list[InstanceMeta]:
    with path.open(newline="", encoding="utf-8") as input_file:
        reader = csv.DictReader(input_file)
        rows: list[InstanceMeta] = []
        for line_no, row in enumerate(reader, 2):
            width = int(row["width"], 0)
            if width <= 0:
                raise ValueError(f"{path}:{line_no}: width must be positive")
            rows.append(
                InstanceMeta(
                    row["instance_name"].strip(),
                    row["coverage_signal_name"].strip(),
                    width,
                    parse_distance(row["distance"]),
                )
            )
    if not rows:
        raise ValueError(f"{path}: metadata is empty")
    if not any(row.is_target for row in rows):
        raise ValueError(f"{path}: metadata has no target instance at distance 0")
    return rows


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
            return {"target_covered_bits": "", "distance": "", "energy": "", "new_coverage": "", "target_progress": ""}
        if len(coverage) != len(self.metadata):
            raise ValueError("coverage length does not match DirectFuzz metadata length")

        target_bits = 0
        reachable_bits = 0
        weighted = 0
        new_cov = False
        target_progress = False
        for idx, (meta, data) in enumerate(zip(self.metadata, coverage)):
            bits = count_bits_with_width(data, meta.width)
            if meta.is_target:
                target_bits += bits
            old = self.accumulated[idx]
            for byte_idx, byte in enumerate(data):
                new_bits = byte & (~old[byte_idx] & 0xFF)
                if new_bits:
                    new_cov = True
                    if meta.is_target:
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
            "distance": "" if distance is None else round(distance, 6),
            "energy": round(energy, 6),
            "new_coverage": new_cov,
                "target_progress": target_progress,
            }


def load_direct_coverage_file(path: Path, metadata: list[InstanceMeta]) -> list[bytes]:
    """Load native DirectFuzz coverage rows in metadata order.

    The CSV schema is intentionally simple for the first LinkNan ABI:
    `instance_name,coverage_hex`. Each `coverage_hex` payload must match the
    corresponding metadata row width after padding bits are masked.
    """
    by_instance: dict[str, bytes] = {}
    with path.open(newline="", encoding="utf-8") as input_file:
        reader = csv.DictReader(input_file)
        for line_no, row in enumerate(reader, 2):
            instance = row["instance_name"].strip()
            raw_hex = row["coverage_hex"].strip()
            try:
                data = bytes.fromhex(raw_hex)
            except ValueError as exc:
                raise ValueError(f"{path}:{line_no}: invalid coverage_hex for {instance}") from exc
            by_instance[instance] = data

    coverage: list[bytes] = []
    for meta in metadata:
        if meta.instance not in by_instance:
            raise ValueError(f"{path}: missing coverage for instance {meta.instance!r}")
        data = by_instance[meta.instance]
        if len(data) != meta.byte_len:
            raise ValueError(
                f"{path}: instance {meta.instance!r} coverage has {len(data)} bytes, expected {meta.byte_len}"
            )
        mutable = bytearray(data)
        mask_padding_bits(mutable, meta.width)
        coverage.append(bytes(mutable))
    return coverage


def run_directfuzz(args: Any, ctx: VcsContext) -> int:
    work_dir = args.work_dir.expanduser().resolve()
    runs_dir = work_dir / "runs"
    logs_dir = work_dir / "logs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    seeds = collect_seed_paths(args.seed, args.seed_list, args.seed_dir, work_dir, args.limit, True, "directfuzz-smoke")
    metadata = load_direct_metadata(args.metadata.expanduser())
    if not any(row.instance == args.target_instance and row.is_target for row in metadata):
        raise ValueError(f"{args.metadata}: target instance {args.target_instance!r} is not present at distance 0")

    state = DirectCoverageState(metadata)
    build_simv_if_needed(args, ctx, work_dir)
    rows: list[dict[str, Any]] = []
    for idx, seed in enumerate(seeds):
        case_name = f"{slugify(args.case_prefix)}-{idx:04d}-{slugify(seed.stem)}"
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
        paper_faithful = False
        required_native_abi = "directfuzz_per_instance_mux_toggle"
        if args.coverage_backend == "native-file":
            if not args.native_coverage:
                raise ValueError("--coverage-backend native-file requires --native-coverage")
            feedback = state.feedback(load_direct_coverage_file(args.native_coverage.expanduser(), metadata))
            backend = "directfuzz_per_instance_mux_toggle_file"
            notes = "真实 LinkNan VCS 已运行;覆盖/反馈来自 DirectFuzz per-instance mux-toggle ABI 导出文件"
            paper_faithful = True
            required_native_abi = ""
        elif args.coverage_backend == "dev-mock":
            feedback = state.feedback(dev_direct_coverage(seed, metadata, args.target_instance))
            backend = "dev_mock_directfuzz_feedback"
            notes = (
                "真实 LinkNan VCS 已运行;"
                "当前覆盖/反馈为 deterministic dev mock，仅用于调试数据管线;"
                "必须接入论文定义的 DirectFuzz per-instance mux-toggle 覆盖/反馈 ABI 后，"
                "才能作为 paper-faithful DirectFuzz 数据"
            )
        else:
            feedback = state.feedback(None)
            backend = "vcs_log_no_directfuzz_coverage"
            notes = (
                "真实 LinkNan VCS 已运行;"
                "当前 VCS log 不提供论文定义的 DirectFuzz per-instance mux-toggle 覆盖/反馈;"
                "必须接入论文定义的真实覆盖/反馈 ABI"
            )
        rows.append(
            {
                "fuzzer": "directfuzz",
                "seed": str(seed),
                "target_instance": args.target_instance,
                "wall_time_sec": round(result.wall_time_sec, 6),
                "cycles": info.cycles or ctx.cycles,
                "exit_code": result.returncode,
                "coverage_backend": backend,
                **feedback,
                "log_path": str(run_log),
                "paper_faithful": paper_faithful,
                "required_native_abi": required_native_abi,
                "notes": append_notes(notes, {"sfuz_seen": info.sfuz_expansion_seen, "vcs_report": info.vcs_report_seen}),
            }
        )
    write_table(
        rows,
        args.output_json or work_dir / "results.json",
        args.output_csv or work_dir / "results.csv",
        DIRECTFUZZ_FIELDS,
        {"fuzzer": "directfuzz"},
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
