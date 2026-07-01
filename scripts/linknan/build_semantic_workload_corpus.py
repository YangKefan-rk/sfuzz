#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import random
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from linknan.common import slugify
    from linknan.sfuzz_scenarios import ScenarioIR, generate_scenario, write_scenario_artifacts
    from linknan.surgefuzz_program import DEFAULT_RISCV_GCC, DEFAULT_RISCV_OBJCOPY, resolve_tool
else:
    from .common import slugify
    from .sfuzz_scenarios import ScenarioIR, generate_scenario, write_scenario_artifacts
    from .surgefuzz_program import DEFAULT_RISCV_GCC, DEFAULT_RISCV_OBJCOPY, resolve_tool


FIELDNAMES = (
    "testcase_id",
    "source",
    "category",
    "input_path",
    "input_format",
    "file_size",
    "applicable_fuzzers",
    "sfuzz_seed_path",
    "rfuzz_workload_path",
    "directfuzz_workload_path",
    "surgefuzz_workload_path",
    "conversion_command",
    "expected_run_mode",
    "sha256",
    "notes",
)

COMMON_SCENARIOS: tuple[tuple[str, str], ...] = (
    ("memory_alias", "insert_load_store_pair"),
    ("cacheline_conflict", "create_same_cacheline_alias"),
    ("cacheline_conflict", "create_cross_cacheline_alias"),
    ("load_store_dependency", "create_store_load_dependency"),
    ("load_store_dependency", "increase_replay_pressure"),
    ("store_load_reordering", "insert_fence_rw_rw"),
    ("lrsc_success_fail", "insert_lrsc_pair"),
    ("fence_ordering", "insert_fence_rw_rw"),
    ("branch_flush_memory", "insert_branch_around_memory"),
    ("tlb_refill_memory", "insert_tlb_pressure_sequence"),
    ("mshr_pressure", "increase_mshr_pressure"),
    ("queue_backpressure", "increase_store_buffer_pressure"),
)

MULTICORE_SFUZ_DIAGNOSTICS: tuple[tuple[str, str], ...] = (
    ("amo_contention", "insert_amo_sequence"),
    ("cacheline_conflict", "insert_multicore_pingpong"),
    ("lrsc_success_fail", "force_sc_fail_window"),
    ("fence_ordering", "insert_fence_before_after_amo"),
)

CATEGORY_BY_FAMILY = {
    "memory_alias": "load/store queue stress",
    "cacheline_conflict": "cache/memory/NoC/AXI stress",
    "load_store_dependency": "load/store queue stress",
    "store_load_reordering": "AMO/misaligned/memory ordering",
    "lrsc_success_fail": "AMO/misaligned/memory ordering",
    "fence_ordering": "AMO/misaligned/memory ordering",
    "branch_flush_memory": "branch/flush/replay",
    "tlb_refill_memory": "cache/memory/NoC/AXI stress",
    "mshr_pressure": "cache/memory/NoC/AXI stress",
    "queue_backpressure": "load/store queue stress",
    "amo_contention": "AMO/misaligned/memory ordering",
}


@dataclass(frozen=True)
class ScenarioSpec:
    family: str
    operator: str


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as input_file:
        for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scenario_specs(include_multicore: bool = False) -> list[ScenarioSpec]:
    raw_specs = COMMON_SCENARIOS + (MULTICORE_SFUZ_DIAGNOSTICS if include_multicore else ())
    return [ScenarioSpec(family, operator) for family, operator in raw_specs]


def compile_assembly(
    asm_path: Path,
    *,
    output_elf: Path,
    output_bin: Path,
    gcc: str | None = None,
    objcopy: str | None = None,
    link_address: int = 0x80000000,
) -> str:
    gcc_bin = resolve_tool(gcc, DEFAULT_RISCV_GCC)
    objcopy_bin = resolve_tool(objcopy, DEFAULT_RISCV_OBJCOPY)
    output_elf.parent.mkdir(parents=True, exist_ok=True)
    output_bin.parent.mkdir(parents=True, exist_ok=True)
    compile_cmd = [
        gcc_bin,
        "-nostdlib",
        "-nostartfiles",
        "-march=rv64imac",
        "-mabi=lp64",
        f"-Wl,-Ttext={link_address:#x}",
        "-Wl,-N",
        "-Wl,--no-relax",
        "-o",
        str(output_elf),
        str(asm_path),
    ]
    objcopy_cmd = [objcopy_bin, "-O", "binary", str(output_elf), str(output_bin)]
    subprocess.run(compile_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    subprocess.run(objcopy_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return " && ".join(" ".join(part) for part in (compile_cmd, objcopy_cmd))


def write_core0_bin(scenario: ScenarioIR, output_bin: Path) -> str:
    output_bin.parent.mkdir(parents=True, exist_ok=True)
    output_bin.write_bytes(scenario.core_payload(0))
    return f"write core0 payload ({len(scenario.core_payload(0))} bytes)"


def write_manifest(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)


def build_common_rows(args: argparse.Namespace) -> list[dict[str, str]]:
    rnd = random.Random(args.rng_seed)
    rows: list[dict[str, str]] = []
    specs = scenario_specs(False)
    for variant_round in range(max(1, args.variants_per_scenario)):
        for spec_index, spec in enumerate(specs):
            if args.limit > 0 and len(rows) >= args.limit:
                return rows
            variant = args.variant_base + variant_round * len(specs) + spec_index
            scenario = generate_scenario(
                spec.family,
                operator=spec.operator,
                variant=variant,
                rng=rnd,
                core1_handoff_enabled=False,
                runtime_profile="long",
                stress_iterations=args.stress_iterations,
                target_min_wall_time_sec=args.target_min_wall_time_sec,
            )
            testcase_id = f"sc{len(rows):04d}-{slugify(scenario.scenario_id)}"
            sfuz_path = args.output_dir / "sfuz" / f"{testcase_id}.sfuz"
            workload_dir = args.output_dir / "workloads"
            workload_base = workload_dir / testcase_id
            _sfuz, asm_path, _meta_path = write_scenario_artifacts(sfuz_path, scenario)
            assert asm_path is not None

            if args.input_format == "elf":
                workload_path = workload_base.with_suffix(".elf")
                bin_path = workload_base.with_suffix(".bin")
                conversion = compile_assembly(
                    asm_path,
                    output_elf=workload_path,
                    output_bin=bin_path,
                    gcc=args.riscv_gcc,
                    objcopy=args.objcopy,
                )
            else:
                workload_path = workload_base.with_suffix(".bin")
                conversion = write_core0_bin(scenario, workload_path)

            rows.append(
                {
                    "testcase_id": testcase_id,
                    "source": "sfuzz-semantic-scenario",
                    "category": CATEGORY_BY_FAMILY.get(spec.family, "load/store queue stress"),
                    "input_path": str(workload_path),
                    "input_format": args.input_format,
                    "file_size": str(workload_path.stat().st_size),
                    "applicable_fuzzers": "sfuzz,rfuzz,directfuzz,surgefuzz",
                    "sfuzz_seed_path": str(sfuz_path),
                    "rfuzz_workload_path": str(workload_path),
                    "directfuzz_workload_path": str(workload_path),
                    "surgefuzz_workload_path": str(workload_path),
                    "conversion_command": conversion,
                    "expected_run_mode": "vcs-workload-semantic-scenario",
                    "sha256": sha256_file(workload_path),
                    "notes": "; ".join(
                        [
                            f"scenario_family={scenario.scenario_family}",
                            f"operator={scenario.semantic_operator}",
                            f"runtime_profile={scenario.runtime_profile}",
                            f"stress_iterations={scenario.stress_iterations}",
                            "common four-fuzzer gate uses core0-only workload; multicore SFuzz diagnostics are generated separately",
                        ]
                    ),
                }
            )
    return rows


def build_multicore_diagnostics(args: argparse.Namespace) -> list[Path]:
    diagnostic_dir = args.output_dir / "sfuz-multicore-diagnostics"
    if diagnostic_dir.exists() and args.clean:
        shutil.rmtree(diagnostic_dir)
    diagnostic_dir.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    rnd = random.Random(args.rng_seed + 1009)
    for index, (family, operator) in enumerate(MULTICORE_SFUZ_DIAGNOSTICS):
        scenario = generate_scenario(
            family,
            operator=operator,
            variant=args.variant_base + index,
            rng=rnd,
            core1_handoff_enabled=True,
            runtime_profile="long",
            stress_iterations=args.multicore_stress_iterations,
            target_min_wall_time_sec=args.target_min_wall_time_sec,
        )
        output = diagnostic_dir / f"mc{index:04d}-{slugify(scenario.scenario_id)}.sfuz"
        write_scenario_artifacts(output, scenario)
        paths.append(output)
    list_path = args.output_dir / "sfuzz_multicore_seed_list.txt"
    list_path.write_text("\n".join(str(path) for path in paths) + ("\n" if paths else ""), encoding="utf-8")
    return paths


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build same-origin semantic SFuzz/LinkNan workloads for T2 gates")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=None)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--variants-per-scenario", type=int, default=1)
    parser.add_argument("--variant-base", type=int, default=0)
    parser.add_argument("--rng-seed", type=int, default=20260605)
    parser.add_argument("--target-min-wall-time-sec", type=int, default=300)
    parser.add_argument("--stress-iterations", type=int, default=6144)
    parser.add_argument("--multicore-stress-iterations", type=int, default=1536)
    parser.add_argument("--input-format", choices=["elf", "bin"], default="elf")
    parser.add_argument("--riscv-gcc", default="")
    parser.add_argument("--objcopy", default="")
    parser.add_argument("--clean", action="store_true")
    parser.add_argument("--no-multicore-diagnostics", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.output_dir = args.output_dir.expanduser().resolve()
    if args.clean and args.output_dir.exists():
        shutil.rmtree(args.output_dir)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    manifest = (args.manifest or (args.output_dir / "semantic_workload_manifest.csv")).expanduser().resolve()
    rows = build_common_rows(args)
    if not rows:
        raise SystemExit("no semantic workload rows generated")
    write_manifest(manifest, rows)
    diagnostics = [] if args.no_multicore_diagnostics else build_multicore_diagnostics(args)
    print(f"manifest={manifest}")
    print(f"common_workloads={len(rows)}")
    print(f"multicore_sfuz_diagnostics={len(diagnostics)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
