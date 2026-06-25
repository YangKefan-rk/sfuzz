from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
SFUZZ_HOME = SCRIPT_DIR.parents[1]
WORKSPACE_ROOT = SFUZZ_HOME.parent
DEFAULT_CONFIG = SFUZZ_HOME / "config" / "sfuzz.toml"


@dataclass
class VcsContext:
    linknan_root: Path
    build_dir: Path
    sim_dir: Path
    cycles: int | None
    num_cores: str
    build_no_diff: bool
    no_diff: bool
    no_fsdb: bool
    no_xprop: bool
    no_fgp: bool
    no_initreg_random: bool


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
    if not path.is_file():
        return {}
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
    default: Any,
    base: Path | None = None,
) -> Path:
    value = cfg(config, section, key, default)
    path = Path(str(value)).expanduser()
    if base is not None and not path.is_absolute():
        return base / path
    return path


def bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in {"0", "false", "no", "off"}


def context_from_config(args: Any) -> VcsContext:
    config_path = Path(getattr(args, "config", DEFAULT_CONFIG)).expanduser()
    config = load_toml(config_path)
    linknan_default = cfg_path(config, "linknan", "root", WORKSPACE_ROOT / "LinkNan")
    linknan_root = Path(getattr(args, "linknan_root", "") or linknan_default).expanduser().resolve()
    build_dir = Path(
        getattr(args, "build_dir", "")
        or cfg_path(config, "linknan", "build_dir", linknan_root / "build", linknan_root)
    ).expanduser().resolve()
    sim_dir = Path(
        getattr(args, "sim_dir", "")
        or cfg_path(config, "linknan", "sim_dir", linknan_root / "sim", linknan_root)
    ).expanduser().resolve()
    no_cycle_limit = bool(getattr(args, "no_cycle_limit", False))
    cycle_value = getattr(args, "cycles", None)
    if no_cycle_limit:
        cycles = None
    elif cycle_value is not None:
        cycles_value = int(cycle_value)
        cycles = cycles_value if cycles_value > 0 else None
    elif os.environ.get("VCS_CYCLES"):
        cycles_value = int(os.environ["VCS_CYCLES"])
        cycles = cycles_value if cycles_value > 0 else None
    else:
        configured_cycles = cfg(config, "vcs", "cycles", 0)
        cycles = int(configured_cycles) if configured_cycles not in {None, "", 0, "0"} else None
    configured_num_cores = cfg(config, "vcs", "num_cores", cfg(config, "emu", "num_cores", 1))
    num_cores = str(os.environ.get("NUM_CORES", configured_num_cores))
    if bool(getattr(args, "enable_core1_handoff", False)):
        if "NUM_CORES" in os.environ and num_cores == "1":
            raise ValueError("--enable-core1-handoff requires NUM_CORES>=2; got explicit NUM_CORES=1")
        if "NUM_CORES" not in os.environ and num_cores == "1":
            num_cores = "2"
    return VcsContext(
        linknan_root=linknan_root,
        build_dir=build_dir,
        sim_dir=sim_dir,
        cycles=cycles,
        num_cores=num_cores,
        build_no_diff=bool_value(os.environ.get("VCS_BUILD_NO_DIFF", cfg(config, "vcs", "build_no_diff", False))),
        no_diff=bool_value(os.environ.get("VCS_NO_DIFF", cfg(config, "vcs", "no_diff", True))),
        no_fsdb=bool_value(os.environ.get("VCS_NO_FSDB", cfg(config, "vcs", "no_fsdb", True))),
        no_xprop=bool_value(os.environ.get("VCS_NO_XPROP", cfg(config, "vcs", "no_xprop", True))),
        no_fgp=bool_value(os.environ.get("VCS_NO_FGP", cfg(config, "vcs", "no_fgp", True))),
        no_initreg_random=bool_value(os.environ.get("VCS_NO_INITREG_RANDOM", cfg(config, "vcs", "no_initreg_random", True))),
    )
