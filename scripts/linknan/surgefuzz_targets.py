from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import SFUZZ_HOME


DEFAULT_TARGET_MANIFEST = SFUZZ_HOME / "config" / "surgefuzz_targets.toml"


@dataclass(frozen=True)
class SurgeTarget:
    id: str
    category: str
    module: str
    instance: str
    signal: str
    annotation: str
    description: str = ""
    ancestor_selector: str = "distance-nmi"
    max_ancestor_width: int = 64
    ancestor_profile: str = ""
    nmi_threshold: float = 0.85
    preferred_ancestors: tuple[str, ...] = field(default_factory=tuple)


def load_toml(path: Path) -> dict[str, Any]:
    if sys.version_info >= (3, 11):
        import tomllib

        with path.open("rb") as input_file:
            return tomllib.load(input_file)
    try:
        import tomli
    except ImportError as exc:
        return load_simple_target_toml(path)
    with path.open("rb") as input_file:
        return tomli.load(input_file)


def parse_scalar(raw: str) -> Any:
    value = raw.strip()
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [parse_scalar(item) for item in re.split(r"\s*,\s*", inner)]
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    if re.fullmatch(r"[+-]?\d+", value):
        return int(value)
    if re.fullmatch(r"[+-]?\d+\.\d+", value):
        return float(value)
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    return value


def load_simple_target_toml(path: Path) -> dict[str, Any]:
    targets: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line == "[[targets]]":
            current = {}
            targets.append(current)
            continue
        if current is None or "=" not in line:
            raise ValueError(f"{path}:{line_no}: expected [[targets]] or key = value")
        key, value = line.split("=", 1)
        current[key.strip()] = parse_scalar(value)
    return {"targets": targets}


def load_target_manifest(path: Path | None = None) -> list[SurgeTarget]:
    manifest = (path or DEFAULT_TARGET_MANIFEST).expanduser()
    payload = load_toml(manifest)
    targets: list[SurgeTarget] = []
    for raw in payload.get("targets", []):
        preferred = raw.get("preferred_ancestors", [])
        if isinstance(preferred, str):
            preferred_ancestors = tuple(item.strip() for item in re.split(r"[,:\s]+", preferred) if item.strip())
        else:
            preferred_ancestors = tuple(str(item) for item in preferred)
        targets.append(
            SurgeTarget(
                id=str(raw["id"]),
                category=str(raw["category"]),
                module=str(raw["module"]),
                instance=str(raw["instance"]),
                signal=str(raw["signal"]),
                annotation=str(raw.get("annotation", "SURGE_FREQ=1")),
                description=str(raw.get("description", "")),
                ancestor_selector=str(raw.get("ancestor_selector", "distance-nmi")),
                max_ancestor_width=int(raw.get("max_ancestor_width", 64)),
                ancestor_profile=str(raw.get("ancestor_profile", "")),
                nmi_threshold=float(raw.get("nmi_threshold", 0.85)),
                preferred_ancestors=preferred_ancestors,
            )
        )
    if not targets:
        raise ValueError(f"{manifest}: no [[targets]] entries found")
    return targets


def select_target(path: Path | None, target_id: str | None) -> SurgeTarget:
    targets = load_target_manifest(path)
    if not target_id:
        return targets[0]
    for target in targets:
        if target.id == target_id:
            return target
    known = ", ".join(target.id for target in targets)
    raise ValueError(f"unknown SurgeFuzz target id {target_id!r}; known targets: {known}")


def target_env(target: SurgeTarget, ancestors: list[str] | tuple[str, ...] | None = None) -> dict[str, str]:
    env = {
        "SFUZZ_SURGEFUZZ_MODULE": target.module,
        "SFUZZ_SURGEFUZZ_TARGET_INSTANCE": target.instance,
        "SFUZZ_SURGEFUZZ_TARGET": target.signal,
        "SFUZZ_SURGEFUZZ_ANCESTOR_SELECTOR": target.ancestor_selector,
        "SFUZZ_SURGEFUZZ_MAX_ANCESTOR_WIDTH": str(target.max_ancestor_width),
        "SFUZZ_SURGEFUZZ_NMI_THRESHOLD": str(target.nmi_threshold),
    }
    if ancestors:
        env["SFUZZ_SURGEFUZZ_ANCESTORS"] = ",".join(ancestors)
    if target.ancestor_profile:
        env["SFUZZ_SURGEFUZZ_ANCESTOR_PROFILE"] = target.ancestor_profile
    return env


def manifest_table(path: Path | None = None) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for target in load_target_manifest(path):
        rows.append(
            {
                "id": target.id,
                "category": target.category,
                "module": target.module,
                "instance": target.instance,
                "signal": target.signal,
                "annotation": target.annotation,
                "ancestor_selector": target.ancestor_selector,
                "description": target.description,
            }
        )
    return rows
