#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
SFUZZ_HOME = SCRIPT_DIR.parents[1]
WORKSPACE_ROOT = SFUZZ_HOME.parent
HOME = Path.home()

DEFAULT_RISCV_ISA = HOME / "riscv-tests" / "isa"
DEFAULT_LITMUS_RISCV = HOME / "Nanhu-V5.1" / "litmus-tests-riscv"
DEFAULT_NEXUS_LITMUS = HOME / "nexus-am" / "cases" / "litmus"
DEFAULT_LINKNAN_READY = WORKSPACE_ROOT / "LinkNan" / "ready-to-run"
DEFAULT_MANIFEST = SFUZZ_HOME / "benchmarks" / "linknan" / "phase1_corpus_manifest.csv"
DEFAULT_SFUZ_DIR = SFUZZ_HOME / "work" / "bench" / "linknan-corpus" / "sfuz"

# riscv-tests whose ISA features the LinkNan/Nanhu core does not implement.
# The hypervisor (H) extension is unsupported, so hypervisor-* tests trap early
# and report a spurious HTIF failure code; exclude them from the corpus.
# NOTE: rv64*-v-* are virtual-memory (Sv39) variants, NOT H-extension, and are
# kept on purpose (the core supports Sv39).
UNSUPPORTED_ISA_PREFIXES = ("hypervisor",)

CATEGORIES = (
    "ISA basic instructions",
    "CSR/exception",
    "AMO/misaligned/memory ordering",
    "branch/flush/replay",
    "load/store queue stress",
    "cache/memory/NoC/AXI stress",
    "microbenchmark",
)

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


@dataclass(frozen=True)
class Candidate:
    source: str
    category: str
    input_path: Path
    input_format: str
    expected_run_mode: str
    notes: str = ""


def slugify(text: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", text).strip("-")
    return slug or "testcase"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_format(path: Path) -> str:
    try:
        magic = path.read_bytes()[:4]
    except OSError:
        return "unknown"
    if magic == b"\x7fELF":
        return "elf"
    if path.suffix == ".litmus":
        return "litmus"
    return "bin"


def category_for_name(name: str, source: str) -> str:
    lower = name.lower()
    if source == "linknan-ready-to-run":
        if any(item in lower for item in ("coremark", "dhrystone", "microbench")):
            return "microbenchmark"
        if any(item in lower for item in ("linux", "flash", "copy")):
            return "cache/memory/NoC/AXI stress"
    if any(item in lower for item in ("csr", "scall", "sbreak", "illegal", "breakpoint", "trap", "exception")):
        return "CSR/exception"
    if any(item in lower for item in ("misaligned", "amo", "lrsc", "lr-sc", "fence", "litmus", "mp", "sb", "lb", "wrc", "dekker")):
        return "AMO/misaligned/memory ordering"
    if any(item in lower for item in ("bge", "bgeu", "beq", "bne", "blt", "bltu", "jal", "jalr", "branch", "flush", "replay")):
        return "branch/flush/replay"
    if any(item in lower for item in ("ld", "st", "load", "store", "lw", "lh", "lb", "lbu", "lhu", "lwu", "sd", "sw", "sh", "sb")):
        return "load/store queue stress"
    if any(item in lower for item in ("cache", "axi", "noc", "tlb", "pmp", "ptw", "icache", "dcache", "flash", "linux")):
        return "cache/memory/NoC/AXI stress"
    return "ISA basic instructions"


def collect_riscv_isa(root: Path) -> list[Candidate]:
    if not root.is_dir():
        return []
    candidates: list[Candidate] = []
    for path in sorted(root.iterdir()):
        if not path.is_file() or path.name.startswith(".") or path.suffix == ".dump":
            continue
        if path.name.startswith(UNSUPPORTED_ISA_PREFIXES):
            continue
        fmt = file_format(path)
        if fmt != "elf":
            continue
        candidates.append(
            Candidate(
                source="riscv-tests-isa",
                category=category_for_name(path.name, "riscv-tests-isa"),
                input_path=path.resolve(),
                input_format=fmt,
                expected_run_mode="vcs-workload",
            )
        )
    return candidates


def collect_linknan_ready(root: Path) -> list[Candidate]:
    if not root.is_dir():
        return []
    candidates: list[Candidate] = []
    for path in sorted(root.iterdir()):
        if not path.is_file() or path.suffix.lower() not in {".bin", ".elf", ""}:
            continue
        fmt = file_format(path)
        candidates.append(
            Candidate(
                source="linknan-ready-to-run",
                category=category_for_name(path.name, "linknan-ready-to-run"),
                input_path=path.resolve(),
                input_format=fmt,
                expected_run_mode="vcs-workload",
            )
        )
    return candidates


def collect_nexus_litmus(root: Path) -> list[Candidate]:
    build = root / "build"
    if not build.is_dir():
        return []
    candidates: list[Candidate] = []
    seen_stems: set[str] = set()
    for path in sorted(build.glob("*.bin")) + sorted(build.glob("*.elf")):
        if not path.is_file() or path.stem in seen_stems:
            continue
        seen_stems.add(path.stem)
        candidates.append(
            Candidate(
                source="nexus-am-litmus-build",
                category=category_for_name(path.name, "nexus-am-litmus-build"),
                input_path=path.resolve(),
                input_format=file_format(path),
                expected_run_mode="vcs-workload",
            )
        )
    return candidates


def collect_litmus_sources(root: Path) -> list[Candidate]:
    tests = root / "tests"
    if not tests.is_dir():
        return []
    candidates: list[Candidate] = []
    for path in sorted(tests.rglob("*.litmus")):
        candidates.append(
            Candidate(
                source="litmus-tests-riscv-source",
                category=category_for_name(path.name, "litmus-tests-riscv-source"),
                input_path=path.resolve(),
                input_format="litmus",
                expected_run_mode="litmus-source-conversion-required",
                notes="logical testcase; generate C/ELF/bin before VCS execution",
            )
        )
    return candidates


def select_balanced(candidates: list[Candidate], total: int) -> list[Candidate]:
    if total <= 0 or len(candidates) <= total:
        return candidates
    buckets: dict[str, list[Candidate]] = {category: [] for category in CATEGORIES}
    for candidate in candidates:
        buckets.setdefault(candidate.category, []).append(candidate)

    selected: list[Candidate] = []
    seen: set[Path] = set()
    while len(selected) < total:
        made_progress = False
        for category in CATEGORIES:
            bucket = buckets.get(category, [])
            while bucket:
                candidate = bucket.pop(0)
                if candidate.input_path not in seen:
                    selected.append(candidate)
                    seen.add(candidate.input_path)
                    made_progress = True
                    break
            if len(selected) >= total:
                break
        if not made_progress:
            break
    return selected


def sfuz_command(candidate: Candidate, output: Path) -> list[str]:
    command = [
        "python3",
        str(SFUZZ_HOME / "scripts" / "make_sfuz_seed.py"),
        "--output",
        str(output),
        "--name",
        output.stem,
        "--description",
        f"Phase 1 corpus seed converted from {candidate.source}:{candidate.input_path.name}",
        "--tag",
        "phase1-corpus",
        "--tag",
        slugify(candidate.category),
        "--tag",
        candidate.source,
    ]
    if candidate.input_format == "elf":
        command.extend(["--core0-elf", str(candidate.input_path)])
    else:
        command.extend(["--core0-bin", str(candidate.input_path)])
    return command


def command_text(command: list[str]) -> str:
    return " ".join(command)


def generate_sfuz(candidate: Candidate, testcase_id: str, sfuz_dir: Path, dry_run: bool) -> tuple[str, str, str]:
    if candidate.input_format == "litmus":
        out_dir = SFUZZ_HOME / "work" / "bench" / "linknan-corpus" / "litmus-generated"
        command = [
            "python3",
            str(SFUZZ_HOME / "scripts" / "litmus_to_c.py"),
            str(candidate.input_path),
            "--output-dir",
            str(out_dir),
            "--litmus-home",
            str(DEFAULT_LITMUS_RISCV),
        ]
        return "", command_text(command), "conversion-required"

    output = sfuz_dir / f"{testcase_id}.sfuz"
    command = sfuz_command(candidate, output)
    if not dry_run:
        output.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    return str(output), command_text(command), "generated" if output.exists() else "declared"


def build_rows(args: argparse.Namespace) -> list[dict[str, str]]:
    executable_candidates: list[Candidate] = []
    executable_candidates.extend(collect_linknan_ready(args.linknan_ready))
    executable_candidates.extend(collect_nexus_litmus(args.nexus_litmus))
    executable_candidates.extend(collect_riscv_isa(args.riscv_isa))
    executable_candidates = select_balanced(executable_candidates, args.max_executable)

    litmus_candidates = select_balanced(collect_litmus_sources(args.litmus_riscv), args.max_litmus_sources)
    candidates = executable_candidates + litmus_candidates

    rows: list[dict[str, str]] = []
    for index, candidate in enumerate(candidates):
        testcase_id = f"tc{index:04d}-{slugify(candidate.source)}-{slugify(candidate.input_path.stem)[:80]}"
        try:
            sfuz_path, conversion, sfuz_status = generate_sfuz(candidate, testcase_id, args.sfuz_dir, args.dry_run)
            notes = candidate.notes
        except subprocess.CalledProcessError as exc:
            sfuz_path = ""
            conversion = command_text(exc.cmd if isinstance(exc.cmd, list) else [str(exc.cmd)])
            sfuz_status = "sfuz-generation-failed"
            notes = f"{candidate.notes}; sfuz stderr={exc.stderr.strip() if exc.stderr else ''}".strip("; ")

        executable = candidate.input_format != "litmus"
        workload_path = str(candidate.input_path) if executable else ""
        applicable = "sfuzz,rfuzz,directfuzz,surgefuzz"
        if candidate.input_format == "litmus":
            applicable = "sfuzz,rfuzz,directfuzz,surgefuzz-after-conversion"

        rows.append(
            {
                "testcase_id": testcase_id,
                "source": candidate.source,
                "category": candidate.category,
                "input_path": str(candidate.input_path),
                "input_format": candidate.input_format,
                "file_size": str(candidate.input_path.stat().st_size),
                "applicable_fuzzers": applicable,
                "sfuzz_seed_path": sfuz_path,
                "rfuzz_workload_path": workload_path,
                "directfuzz_workload_path": workload_path,
                "surgefuzz_workload_path": workload_path,
                "conversion_command": conversion,
                "expected_run_mode": candidate.expected_run_mode,
                "sha256": sha256_file(candidate.input_path),
                "notes": f"sfuz={sfuz_status}" + (f"; {notes}" if notes else ""),
            }
        )
    return rows


def write_manifest(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build the Phase 1 LinkNan corpus manifest and SFUZ seeds")
    parser.add_argument("--riscv-isa", type=Path, default=DEFAULT_RISCV_ISA)
    parser.add_argument("--litmus-riscv", type=Path, default=DEFAULT_LITMUS_RISCV)
    parser.add_argument("--nexus-litmus", type=Path, default=DEFAULT_NEXUS_LITMUS)
    parser.add_argument("--linknan-ready", type=Path, default=DEFAULT_LINKNAN_READY)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--sfuz-dir", type=Path, default=DEFAULT_SFUZ_DIR)
    parser.add_argument("--max-executable", type=int, default=140)
    parser.add_argument("--max-litmus-sources", type=int, default=40)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    rows = build_rows(args)
    if len(rows) < 100:
        raise SystemExit(f"Phase 1 corpus requires at least 100 logical testcases, got {len(rows)}")
    write_manifest(args.manifest, rows)
    by_category: dict[str, int] = {}
    by_source: dict[str, int] = {}
    for row in rows:
        by_category[row["category"]] = by_category.get(row["category"], 0) + 1
        by_source[row["source"]] = by_source.get(row["source"], 0) + 1
    print(f"manifest={args.manifest}")
    print(f"testcases={len(rows)}")
    print("categories=" + ",".join(f"{key}:{by_category[key]}" for key in sorted(by_category)))
    print("sources=" + ",".join(f"{key}:{by_source[key]}" for key in sorted(by_source)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
