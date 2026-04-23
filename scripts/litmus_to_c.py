#!/usr/bin/env python3
import argparse
import os
import shutil
import subprocess
from pathlib import Path

DEFAULT_LITMUS_HOME = Path("/nfs/home/yangkefan/Nanhu-V5.1/litmus-tests-riscv")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert .litmus tests into litmus-generated C source directories"
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        help="one or more .litmus files or directories containing .litmus files",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="root directory for generated litmus source trees",
    )
    parser.add_argument(
        "--litmus-home",
        default=os.environ.get("SFUZZ_LITMUS_HOME", str(DEFAULT_LITMUS_HOME)),
        help="path to the litmus-tests-riscv checkout that provides riscv.cfg",
    )
    parser.add_argument(
        "--riscv-cfg",
        help="override the litmus configuration file passed with -mach",
    )
    parser.add_argument(
        "--litmus-bin",
        default=os.environ.get("LITMUS", "litmus7"),
        help="litmus executable from the diy tool suite",
    )
    parser.add_argument(
        "--litmus-libdir",
        default=os.environ.get("LITMUS_LIBDIR"),
        help="optional litmus libdir; required for just-build herdtools7 binaries when auto-detection fails",
    )
    parser.add_argument(
        "--cores",
        type=int,
        default=2,
        help="value passed to litmus7 -avail",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the commands without executing litmus7",
    )
    return parser.parse_args()


def collect_litmus_files(raw_inputs: list[str]) -> list[Path]:
    collected: list[Path] = []
    seen: set[Path] = set()
    for raw_input in raw_inputs:
        path = Path(raw_input).expanduser()
        if not path.exists():
            raise ValueError(f"input path does not exist: {path}")
        candidates = sorted(path.rglob("*.litmus")) if path.is_dir() else [path]
        for candidate in candidates:
            if candidate.suffix != ".litmus":
                raise ValueError(f"expected a .litmus file, got: {candidate}")
            resolved = candidate.resolve()
            if resolved not in seen:
                seen.add(resolved)
                collected.append(resolved)
    if not collected:
        raise ValueError("no .litmus files were selected")
    return collected


def derive_output_dir(test_path: Path, output_root: Path, tests_root: Path) -> Path:
    try:
        relative = test_path.relative_to(tests_root)
        relative_no_suffix = relative.with_suffix("")
        return output_root.joinpath(relative_no_suffix.parent, relative_no_suffix.name + "-src")
    except ValueError:
        return output_root / (test_path.stem + "-src")


def resolve_litmus_binary(litmus_bin: str, dry_run: bool) -> str:
    path = Path(litmus_bin).expanduser()
    if path.exists():
        return str(path.resolve())
    resolved = shutil.which(litmus_bin)
    if resolved:
        return resolved
    if dry_run:
        return litmus_bin
    raise FileNotFoundError(
        f"{litmus_bin!r} was not found in PATH. Install the diy tool suite or pass --litmus-bin explicitly."
    )


def detect_litmus_libdir(litmus_bin: str, explicit: str | None) -> Path | None:
    if explicit:
        libdir = Path(explicit).expanduser().resolve()
        if not libdir.exists():
            raise FileNotFoundError(f"litmus libdir does not exist: {libdir}")
        return libdir

    binary_path = Path(litmus_bin)
    if not binary_path.exists():
        return None

    for parent in [binary_path.parent, *binary_path.parents]:
        candidate = parent / "litmus" / "libdir"
        if candidate.is_dir():
            return candidate.resolve()
    return None


def main() -> int:
    args = parse_args()
    litmus_home = Path(args.litmus_home).expanduser().resolve()
    riscv_cfg = Path(args.riscv_cfg).expanduser().resolve() if args.riscv_cfg else (litmus_home / "riscv.cfg")
    if not riscv_cfg.exists():
        raise FileNotFoundError(f"RISC-V litmus config does not exist: {riscv_cfg}")
    if args.cores <= 0:
        raise ValueError("--cores must be greater than zero")

    litmus_bin = resolve_litmus_binary(args.litmus_bin, args.dry_run)
    litmus_libdir = detect_litmus_libdir(litmus_bin, args.litmus_libdir)
    tests_root = (litmus_home / "tests").resolve()
    output_root = Path(args.output_dir).expanduser().resolve()
    test_files = collect_litmus_files(args.inputs)

    for test_file in test_files:
        output_dir = derive_output_dir(test_file, output_root, tests_root)
        command = [litmus_bin]
        if litmus_libdir is not None:
            command.extend(["-set-libdir", str(litmus_libdir)])
        command.extend(
            [
                "-mach",
                str(riscv_cfg),
                "-avail",
                str(args.cores),
                "-o",
                str(output_dir),
                str(test_file),
            ]
        )
        print(" ".join(command))
        if args.dry_run:
            continue
        output_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(command, check=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
