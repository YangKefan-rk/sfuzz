#!/usr/bin/env python3
import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
SFUZZ_HOME = SCRIPT_DIR.parent
WORKSPACE_ROOT = SFUZZ_HOME.parent
DEFAULT_CONFIG = SFUZZ_HOME / "config" / "sfuzz.toml"


def parse_scalar(value: str) -> Any:
    value = value.strip()
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1]
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    if re.fullmatch(r"[+-]?\d+", value):
        return int(value)
    return value


def load_simple_toml(path: Path) -> dict[str, dict[str, Any]]:
    config: dict[str, dict[str, Any]] = {}
    section: dict[str, Any] | None = None
    for line_no, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1].strip()
            if not name or "." in name:
                raise ValueError(f"{path}:{line_no}: unsupported TOML section: {raw_line}")
            section = config.setdefault(name, {})
            continue
        if section is None or "=" not in line:
            raise ValueError(f"{path}:{line_no}: expected [section] or key = value")
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"{path}:{line_no}: empty key")
        section[key] = parse_scalar(value)
    return config


def load_toml(path: Path) -> dict[str, dict[str, Any]]:
    if sys.version_info >= (3, 11):
        import tomllib

        with path.open("rb") as toml_file:
            return tomllib.load(toml_file)

    try:
        import tomli
    except ImportError:
        return load_simple_toml(path)

    with path.open("rb") as toml_file:
        return tomli.load(toml_file)


def cfg(config: dict[str, dict[str, Any]], section: str, key: str, default: Any = None) -> Any:
    return config.get(section, {}).get(key, default)


def cfg_path(
    config: dict[str, dict[str, Any]],
    section: str,
    key: str,
    default: Any = None,
    base: Path | None = None,
) -> Path:
    value = cfg(config, section, key, default)
    path = Path(str(value)).expanduser()
    if base is not None and not path.is_absolute():
        return base / path
    return path


def env_value(name: str, default: Any) -> Any:
    return os.environ.get(name, default)


def env_path(name: str, default: Path) -> Path:
    return Path(str(os.environ.get(name, default))).expanduser()


def bool_to_build_flag(value: Any) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    text = str(value).strip().lower()
    return "0" if text in {"0", "false", "no", "off"} else "1"


def require_file(path: Path) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"missing required file: {path}")


def require_dir(path: Path) -> None:
    if not path.is_dir():
        raise FileNotFoundError(f"missing required directory: {path}")


def run(command: list[str | Path], cwd: Path | None = None, stdout: Any = None) -> subprocess.CompletedProcess:
    rendered = [str(item) for item in command]
    print(" ".join(rendered))
    return subprocess.run(rendered, cwd=cwd, check=True, stdout=stdout, stderr=subprocess.STDOUT)


def without_sancov(flags: list[str | Path]) -> list[str | Path]:
    return [
        flag
        for flag in flags
        if str(flag) not in {"-fsanitize-coverage=trace-pc-guard", "-fsanitize-coverage=pc-table"}
    ]


def num_cores_to_noc(num_cores: str) -> str:
    table = {"1": "small", "2": "reduced", "4": "full"}
    if num_cores not in table:
        raise ValueError(f"unsupported NUM_CORES: {num_cores}")
    return table[num_cores]


def discover_objects(real_model_comp: Path) -> list[Path]:
    excluded = {
        "main.o",
        "ram.o",
        "coverage.o",
        "dut.o",
        "verilated.o",
        "verilated_dpi.o",
        "verilated_threads.o",
        "verilated_cov.o",
    }
    objects = sorted(
        path
        for path in real_model_comp.glob("*.o")
        if path.is_file() and path.name not in excluded
    )
    if not objects:
        raise FileNotFoundError(f"no relinkable object files found in {real_model_comp}")
    return objects


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Relink LinkNan with SFuzz and run an ABI smoke check")
    parser.add_argument(
        "--config",
        default=os.environ.get("SFUZZ_CONFIG", str(DEFAULT_CONFIG)),
        help="path to the SFuzz TOML config file",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config_path = Path(args.config).expanduser()
    config = load_toml(config_path) if config_path.is_file() else {}

    default_linknan_root = cfg_path(config, "linknan", "root", WORKSPACE_ROOT / "LinkNan")
    default_linknan_src_root = cfg_path(config, "linknan", "src_root", default_linknan_root, default_linknan_root)
    legacy_release_root = cfg_path(
        config,
        "linknan",
        "legacy_release_root",
        WORKSPACE_ROOT / "LN-release" / "LinkNan_20260324",
    )
    if not default_linknan_src_root.is_dir() and legacy_release_root.is_dir():
        default_linknan_src_root = legacy_release_root

    linknan_root_override = os.environ.get("LINKNAN_ROOT")
    if linknan_root_override:
        linknan_src_root = Path(linknan_root_override).expanduser()
        real_model_root = env_path("REAL_MODEL_ROOT", linknan_src_root)
    else:
        linknan_src_root = env_path(
            "LINKNAN_SRC_ROOT",
            Path(str(env_value("LINKNAN_RELEASE", default_linknan_src_root))).expanduser(),
        )
        real_model_root = env_path(
            "REAL_MODEL_ROOT",
            cfg_path(config, "linknan", "real_model_root", default_linknan_root, default_linknan_root),
        )

    real_model_build_dir = env_path(
        "REAL_MODEL_BUILD_DIR",
        cfg_path(config, "linknan", "build_dir", real_model_root / "build", real_model_root),
    )
    real_model_sim_dir = env_path(
        "REAL_MODEL_SIM_DIR",
        cfg_path(config, "linknan", "sim_dir", real_model_root / "sim", real_model_root),
    )
    real_model_comp = env_path(
        "REAL_MODEL_COMP",
        cfg_path(config, "linknan", "comp_dir", real_model_sim_dir / "emu" / "comp", real_model_root),
    )
    real_model_generated_src = env_path(
        "REAL_MODEL_GENERATED_SRC",
        cfg_path(config, "linknan", "generated_src", real_model_build_dir / "generated-src", real_model_root),
    )

    work_dir = env_path("WORK_DIR", cfg_path(config, "workspace", "work_dir", "/tmp/sfuzz-linknan-abi-smoke"))
    relink_dir = work_dir / "relink"
    corpus_dir = work_dir / "corpus"
    log_file = work_dir / "run.log"
    emu_bin = relink_dir / "emu"

    cxx_bin = str(env_value("CXX", cfg(config, "toolchain", "cxx", "clang++-18")))
    linker = str(cfg(config, "toolchain", "linker", "lld-18"))
    verilator_root = env_path(
        "VERILATOR_ROOT",
        cfg_path(config, "toolchain", "verilator_root", "/nfs/share/opt/verilator/share/verilator"),
    )
    num_cores = str(env_value("NUM_CORES", cfg(config, "emu", "num_cores", 2)))
    emu_thread = str(env_value("EMU_THREAD", cfg(config, "emu", "emu_thread", 8)))
    xmake_jobs = str(env_value("XMAKE_JOBS", cfg(config, "toolchain", "xmake_jobs", 8)))
    build_no_diff = bool_to_build_flag(env_value("BUILD_NO_DIFF", cfg(config, "emu", "build_no_diff", True)))
    coverage_name = str(env_value("COVERAGE_NAME", cfg(config, "coverage", "default", "llvm.branch")))
    use_firrtl_cover = "FIRRTL." in coverage_name

    if shutil.which(cxx_bin) is None:
        raise FileNotFoundError(f"missing required compiler: {cxx_bin}")

    require_dir(linknan_src_root)
    require_file(SFUZZ_HOME / "Cargo.toml")
    require_file(SFUZZ_HOME / "scripts" / "make_sfuz_seed.py")
    require_dir(verilator_root / "include")
    require_dir(verilator_root / "include" / "vltstd")

    if not real_model_comp.is_dir() or not real_model_generated_src.is_dir():
        require_dir(real_model_root)
        require_file(real_model_root / "xmake.lua")
        build_args = [
            "xmake",
            "emu",
            "-o",
            real_model_build_dir,
            "--sim_dir",
            real_model_sim_dir,
            "-j",
            xmake_jobs,
            "-t",
            emu_thread,
            "-N",
            num_cores_to_noc(num_cores),
        ]
        if build_no_diff == "1":
            build_args.append("--no_diff")
        run(build_args, cwd=real_model_root)

    require_dir(real_model_comp)
    require_dir(real_model_generated_src)
    require_file(real_model_comp / "VSimTop.h")
    require_file(real_model_comp / "VSimTop__ALL.a")
    require_file(real_model_comp / "verilated.o")
    require_file(real_model_comp / "verilated_dpi.o")
    require_file(real_model_comp / "verilated_threads.o")
    if use_firrtl_cover:
        require_file(real_model_generated_src / "firrtl-cover.h")
        require_file(real_model_comp / "firrtl-cover.o")

    shutil.rmtree(work_dir, ignore_errors=True)
    relink_dir.mkdir(parents=True, exist_ok=True)
    corpus_dir.mkdir(parents=True, exist_ok=True)

    run(["cargo", "build", "--release", "--locked", "--offline"], cwd=SFUZZ_HOME)

    common_cxxflags: list[str | Path] = [
        "-std=c++17",
        "-DVERILATOR",
        f"-DNUM_CORES={num_cores}",
        f"-I{verilator_root / 'include'}",
        f"-I{verilator_root / 'include' / 'vltstd'}",
        f"-I{real_model_comp}",
        f"-I{linknan_src_root / 'dependencies/difftest/config'}",
        f"-I{real_model_generated_src}",
        f"-I{linknan_src_root / 'dependencies/difftest/src/test/csrc/common'}",
        f"-I{linknan_src_root / 'dependencies/difftest/src/test/csrc/difftest'}",
        f"-I{linknan_src_root / 'dependencies/difftest/src/test/csrc/plugin/spikedasm'}",
        f"-I{linknan_src_root / 'dependencies/difftest/src/test/csrc/verilator'}",
        f'-DNOOP_HOME="{linknan_src_root}"',
        "-DREF_PROXY=NemuProxy",
        f"-DEMU_THREAD={emu_thread}",
        "-DFUZZER_LIB",
        "-DFUZZING",
        "-DLLVM_COVER",
        "-fsanitize-coverage=trace-pc-guard",
        "-fsanitize-coverage=pc-table",
    ]
    if build_no_diff == "1":
        common_cxxflags.append("-DCONFIG_NO_DIFFTEST")
    if use_firrtl_cover:
        common_cxxflags.extend(["-DFIRRTL_COVER", "-DVM_COVERAGE=1"])

    run(
        [
            cxx_bin,
            *common_cxxflags,
            "-c",
            linknan_src_root / "dependencies/difftest/src/test/csrc/common/main.cpp",
            "-o",
            relink_dir / "main.o",
        ]
    )
    run(
        [
            cxx_bin,
            *common_cxxflags,
            "-c",
            linknan_src_root / "dependencies/difftest/src/test/csrc/common/ram.cpp",
            "-o",
            relink_dir / "ram.o",
        ]
    )
    run(
        [
            cxx_bin,
            *without_sancov(common_cxxflags),
            "-c",
            linknan_src_root / "dependencies/difftest/src/test/csrc/common/coverage.cpp",
            "-o",
            relink_dir / "coverage.o",
        ]
    )
    run(
        [
            cxx_bin,
            *common_cxxflags,
            "-c",
            linknan_src_root / "dependencies/difftest/src/test/csrc/common/dut.cpp",
            "-o",
            relink_dir / "dut.o",
        ]
    )

    run(
        [
            "python3",
            SFUZZ_HOME / "scripts" / "make_sfuz_seed.py",
            "--output",
            corpus_dir / "seed.sfuz",
            "--core0-hex",
            "73001000",
            "--name",
            "abi-smoke",
            "--description",
            "minimal SFUZ seed for ABI smoke verification",
        ]
    )

    link_objects: list[Path] = [
        relink_dir / "main.o",
        relink_dir / "ram.o",
        relink_dir / "coverage.o",
        relink_dir / "dut.o",
    ]
    link_objects.extend(discover_objects(real_model_comp))
    if (real_model_comp / "verilated_cov.o").is_file():
        link_objects.append(real_model_comp / "verilated_cov.o")

    run(
        [
            cxx_bin,
            f"-fuse-ld={linker}",
            "-fsanitize-coverage=trace-pc-guard",
            "-fsanitize-coverage=pc-table",
            *link_objects,
            real_model_comp / "verilated.o",
            real_model_comp / "verilated_dpi.o",
            real_model_comp / "verilated_threads.o",
            real_model_comp / "VSimTop__ALL.a",
            "-ldl",
            "-lrt",
            "-lpthread",
            "-lsqlite3",
            "-lz",
            "-lzstd",
            "-latomic",
            SFUZZ_HOME / "target/release/libsfuzz.a",
            "-o",
            emu_bin,
        ]
    )

    run_args = [
        emu_bin,
        "--coverage",
        coverage_name,
        "--fuzzing",
        "--verbose",
        "--max-iters",
        "1",
        "--continue-on-errors",
        "--corpus-input",
        corpus_dir,
    ]

    with log_file.open("w", encoding="utf-8") as log:
        completed = subprocess.run([str(item) for item in run_args], stdout=log, stderr=subprocess.STDOUT)
    log_text = log_file.read_text(encoding="utf-8", errors="replace")
    print(log_text, end="")

    required_lines = [
        "The image is sfuzz-abi-buffer",
        "SFuzz structured seed detected. Expanding image into RAM",
        f"COVERAGE: {coverage_name},",
    ]
    missing = [line for line in required_lines if line not in log_text]
    if missing:
        for line in missing:
            print(f"missing expected proof line: {line}")
        return 1

    print()
    print("SFuzz ABI smoke check passed.")
    print(f"coverage: {coverage_name}")
    print(f"binary: {emu_bin}")
    print(f"seed:   {corpus_dir / 'seed.sfuz'}")
    print(f"log:    {log_file}")
    print(f"emu exit code: {completed.returncode}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
