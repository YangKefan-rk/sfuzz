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
DEFAULT_CONFIG = SCRIPT_DIR / "sfuzz.toml"


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


def bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in {"0", "false", "no", "off"}


def require_file(path: Path) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"missing required file: {path}")


def require_dir(path: Path) -> None:
    if not path.is_dir():
        raise FileNotFoundError(f"missing required directory: {path}")


def run(command: list[str | Path], cwd: Path | None = None) -> subprocess.CompletedProcess:
    rendered = [str(item) for item in command]
    print(" ".join(rendered), flush=True)
    return subprocess.run(rendered, cwd=cwd, check=True)


def num_cores_to_noc(num_cores: str) -> str:
    table = {"1": "small", "2": "reduced", "4": "full"}
    if num_cores not in table:
        raise ValueError(f"unsupported NUM_CORES: {num_cores}")
    return table[num_cores]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build and run a LinkNan VCS SFUZ smoke check")
    parser.add_argument(
        "--config",
        default=os.environ.get("SFUZZ_CONFIG", str(DEFAULT_CONFIG)),
        help="path to the SFuzz TOML config file",
    )
    parser.add_argument("--linknan-root", default=os.environ.get("LINKNAN_ROOT"), help="LinkNan checkout to test")
    parser.add_argument("--seed", type=Path, help="use an existing SFUZ seed instead of generating one")
    parser.add_argument("--work-dir", type=Path, help="directory for generated seed and logs")
    parser.add_argument("--cycles", type=int, help="max VCS simulation cycles")
    parser.add_argument("--case-name", default="sfuzz-vcs-smoke", help="xmake simv-run case name")
    parser.add_argument("--rebuild-comp", action="store_true", help="force VCS recompilation")
    parser.add_argument("--skip-build", action="store_true", help="skip xmake simv and only run the existing simv")
    parser.add_argument("--keep-work-dir", action="store_true", help="preserve the existing smoke work directory")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config_path = Path(args.config).expanduser()
    config = load_toml(config_path) if config_path.is_file() else {}

    default_linknan_root = cfg_path(config, "linknan", "root", WORKSPACE_ROOT / "LinkNan")
    linknan_root = (Path(args.linknan_root).expanduser() if args.linknan_root else default_linknan_root).resolve()

    build_dir = env_path(
        "REAL_MODEL_BUILD_DIR",
        cfg_path(config, "linknan", "build_dir", linknan_root / "build", linknan_root),
    )
    sim_dir = env_path(
        "REAL_MODEL_SIM_DIR",
        cfg_path(config, "linknan", "sim_dir", linknan_root / "sim", linknan_root),
    )
    work_dir = (
        args.work_dir
        or env_path(
        "VCS_WORK_DIR",
        cfg_path(config, "workspace", "vcs_work_dir", "/tmp/sfuzz-linknan-vcs-smoke"),
        )
    ).expanduser().resolve()
    cycles = args.cycles if args.cycles is not None else int(env_value("VCS_CYCLES", cfg(config, "vcs", "cycles", 2000)))
    num_cores = str(env_value("NUM_CORES", cfg(config, "vcs", "num_cores", cfg(config, "emu", "num_cores", 1))))
    no_diff = bool_value(env_value("VCS_NO_DIFF", cfg(config, "vcs", "no_diff", True)))
    no_fsdb = bool_value(env_value("VCS_NO_FSDB", cfg(config, "vcs", "no_fsdb", True)))
    no_xprop = bool_value(env_value("VCS_NO_XPROP", cfg(config, "vcs", "no_xprop", True)))
    no_fgp = bool_value(env_value("VCS_NO_FGP", cfg(config, "vcs", "no_fgp", True)))
    no_initreg_random = bool_value(
        env_value("VCS_NO_INITREG_RANDOM", cfg(config, "vcs", "no_initreg_random", True))
    )

    require_dir(linknan_root)
    require_file(linknan_root / "xmake.lua")
    require_dir(build_dir / "rtl")
    require_dir(build_dir / "generated-src")
    require_file(SFUZZ_HOME / "scripts" / "make_sfuz_seed.py")
    if shutil.which("xmake") is None:
        raise FileNotFoundError("missing required tool: xmake")
    if not args.skip_build and shutil.which("vcs") is None:
        raise FileNotFoundError("missing required tool: vcs")

    if not args.keep_work_dir:
        shutil.rmtree(work_dir, ignore_errors=True)
    work_dir.mkdir(parents=True, exist_ok=True)

    seed = args.seed.expanduser().resolve() if args.seed else work_dir / "seed.sfuz"
    if args.seed:
        require_file(seed)
    else:
        run(
            [
                "python3",
                SFUZZ_HOME / "scripts" / "make_sfuz_seed.py",
                "--output",
                seed,
                "--core0-hex",
                "73001000",
                "--name",
                "vcs-smoke",
                "--description",
                "minimal SFUZ seed for LinkNan VCS smoke",
            ]
        )

    comp_dir = sim_dir / "simv" / "comp"
    if not args.skip_build:
        build_args: list[str | Path] = [
            "xmake",
            "simv",
            "--no_build_chisel",
            f"--noc={num_cores_to_noc(num_cores)}",
            f"--sim_dir={sim_dir}",
            f"--build_dir={build_dir}",
        ]
        if no_diff:
            build_args.append("--no_diff")
        if no_fsdb:
            build_args.append("--no_fsdb")
        if no_xprop:
            build_args.append("--no_xprop")
        if no_fgp:
            build_args.append("--no_fgp")
        if no_initreg_random:
            build_args.append("--no_initreg_random")
        if args.rebuild_comp:
            build_args.append("--rebuild_comp")
        run(build_args, cwd=linknan_root)

    require_file(comp_dir / "simv")

    run_args: list[str | Path] = [
        "xmake",
        "simv-run",
        f"--workload={seed}",
        f"--cycles={cycles}",
        f"--case_name={args.case_name}",
        f"--sim_dir={sim_dir}",
        f"--run_dir={work_dir}",
    ]
    if no_diff:
        run_args.append("--no_diff")
    if no_fsdb:
        run_args.append("--no_dump")
    if no_fgp:
        run_args.append("--no_fgp")
    run(run_args, cwd=linknan_root)

    run_log = work_dir / args.case_name / "run.log"
    assert_log = work_dir / args.case_name / "assert.log"
    require_file(run_log)
    log_text = run_log.read_text(encoding="utf-8", errors="replace")
    required_lines = [
        f"The image is {seed}",
        "SFuzz structured seed detected. Expanding image into RAM",
        "V C S   S i m u l a t i o n   R e p o r t",
    ]
    missing = [line for line in required_lines if line not in log_text]
    if missing:
        for line in missing:
            print(f"missing expected proof line: {line}")
        print(f"log: {run_log}")
        return 1
    if assert_log.is_file() and assert_log.stat().st_size != 0:
        print(f"non-empty assert log: {assert_log}")
        return 1

    print()
    print("LinkNan VCS SFUZ smoke check passed.")
    print(f"linknan: {linknan_root}")
    print(f"simv:    {comp_dir / 'simv'}")
    print(f"seed:    {seed}")
    print(f"log:     {run_log}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
