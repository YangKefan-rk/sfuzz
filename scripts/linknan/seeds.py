from __future__ import annotations

import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .common import require_dir, require_file
from .config import SFUZZ_HOME


DEFAULT_SMOKE_HEX = "73001000"
SFUZ_MAGIC = b"SFUZ"
SFUZ_VERSION = 1


@dataclass
class SfuzSeed:
    core0_prog: bytes
    core1_prog: bytes
    shared_mem_init: list[tuple[int, bytes]]
    interrupt_plan_raw: list[bytes]
    name: str
    description: str
    tags: list[str]


def parse_hex_blob(text: str) -> bytes:
    cleaned = text.strip().replace("_", "").replace(" ", "")
    if cleaned.startswith(("0x", "0X")):
        cleaned = cleaned[2:]
    if len(cleaned) % 2:
        raise ValueError(f"hex payload must contain an even number of digits: {text!r}")
    return bytes.fromhex(cleaned)


def read_seed_metadata_name(seed: Path) -> str:
    try:
        data = seed.read_bytes()
        cursor = 0

        def take(size: int) -> bytes:
            nonlocal cursor
            if cursor + size > len(data):
                raise ValueError("short SFUZ file")
            chunk = data[cursor : cursor + size]
            cursor += size
            return chunk

        def u16() -> int:
            return struct.unpack("<H", take(2))[0]

        def u32() -> int:
            return struct.unpack("<I", take(4))[0]

        def skip_blob() -> None:
            nonlocal cursor
            size = u32()
            if cursor + size > len(data):
                raise ValueError("blob exceeds file size")
            cursor += size

        def read_string() -> str:
            size = u32()
            raw = take(size)
            return raw.decode("utf-8", errors="replace")

        if take(4) != SFUZ_MAGIC:
            return seed.stem
        version = u16()
        _flags = u16()
        if version != SFUZ_VERSION:
            return seed.stem
        skip_blob()
        skip_blob()
        shared_count = u32()
        for _ in range(shared_count):
            take(8)
            skip_blob()
        interrupt_count = u32()
        for _ in range(interrupt_count):
            take(24)
        name = read_string().strip()
        return name or seed.stem
    except Exception:
        return seed.stem


def read_sfuz_seed(seed: Path) -> SfuzSeed:
    data = seed.read_bytes()
    cursor = 0

    def take(size: int) -> bytes:
        nonlocal cursor
        if cursor + size > len(data):
            raise ValueError(f"{seed}: short SFUZ file")
        chunk = data[cursor : cursor + size]
        cursor += size
        return chunk

    def u16() -> int:
        return struct.unpack("<H", take(2))[0]

    def u32() -> int:
        return struct.unpack("<I", take(4))[0]

    def u64() -> int:
        return struct.unpack("<Q", take(8))[0]

    def blob() -> bytes:
        size = u32()
        return take(size)

    def string() -> str:
        return blob().decode("utf-8", errors="replace")

    if take(4) != SFUZ_MAGIC:
        raise ValueError(f"{seed}: invalid SFUZ magic")
    version = u16()
    _flags = u16()
    if version != SFUZ_VERSION:
        raise ValueError(f"{seed}: unsupported SFUZ version {version}")

    core0_prog = blob()
    core1_prog = blob()

    shared_mem_init: list[tuple[int, bytes]] = []
    for _ in range(u32()):
        shared_mem_init.append((u64(), blob()))

    interrupt_plan_raw = [take(24) for _ in range(u32())]
    name = string()
    description = string()
    tags = [string() for _ in range(u32())]
    return SfuzSeed(core0_prog, core1_prog, shared_mem_init, interrupt_plan_raw, name, description, tags)


def write_sfuz_seed(output: Path, seed: SfuzSeed) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)

    def u16(value: int) -> bytes:
        return struct.pack("<H", value)

    def u32(value: int) -> bytes:
        if not 0 <= value <= 0xFFFFFFFF:
            raise ValueError(f"value does not fit in u32: {value}")
        return struct.pack("<I", value)

    def u64(value: int) -> bytes:
        return struct.pack("<Q", value)

    def blob(value: bytes) -> bytes:
        return u32(len(value)) + value

    def string(value: str) -> bytes:
        return blob(value.encode("utf-8"))

    with output.open("wb") as out:
        out.write(SFUZ_MAGIC)
        out.write(u16(SFUZ_VERSION))
        out.write(u16(0))
        out.write(blob(seed.core0_prog))
        out.write(blob(seed.core1_prog))
        out.write(u32(len(seed.shared_mem_init)))
        for base_addr, data in seed.shared_mem_init:
            out.write(u64(base_addr))
            out.write(blob(data))
        out.write(u32(len(seed.interrupt_plan_raw)))
        for event in seed.interrupt_plan_raw:
            if len(event) != 24:
                raise ValueError(f"SFUZ interrupt event must be 24 bytes, got {len(event)}")
            out.write(event)
        out.write(string(seed.name))
        out.write(string(seed.description))
        out.write(u32(len(seed.tags)))
        for tag in seed.tags:
            out.write(string(tag))


def seed_category(seed: Path, seed_name: str | None = None) -> str:
    name = (seed_name or seed.stem).strip() or seed.stem
    parts = name.split("-")
    if len(parts) >= 2:
        return f"{parts[0]}-{parts[1]}"
    return parts[0] if parts else seed.stem


def make_sfuz_seed(output: Path, core0_hex: str, name: str, tags: Iterable[str] = ()) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "python3",
        str(SFUZZ_HOME / "scripts" / "make_sfuz_seed.py"),
        "--output",
        str(output),
        "--core0-hex",
        core0_hex,
        "--name",
        name,
        "--description",
        f"generated by LinkNan runner for {name}",
    ]
    for tag in tags:
        command.extend(["--tag", tag])
    subprocess.run(command, check=True)


def collect_seed_paths(
    seed_args: list[str],
    seed_list: Path | None,
    seed_dir: Path | None,
    work_dir: Path,
    limit: int = 0,
    generate_smoke: bool = True,
    smoke_name: str = "vcs-smoke",
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
        require_dir(seed_dir)
        seeds.extend(sorted(seed_dir.glob("*.sfuz")))

    if not seeds and generate_smoke:
        generated = work_dir / "seeds" / "smoke.sfuz"
        make_sfuz_seed(generated, DEFAULT_SMOKE_HEX, smoke_name, tags=["generated", "smoke"])
        seeds.append(generated)

    resolved: list[Path] = []
    seen: set[Path] = set()
    for seed in seeds:
        path = seed.resolve()
        require_file(path)
        if path not in seen:
            resolved.append(path)
            seen.add(path)
    return resolved[:limit] if limit > 0 else resolved


def seed_from_raw_hex(raw_hex: str, work_dir: Path, case_name: str) -> tuple[Path, bytes]:
    raw = parse_hex_blob(raw_hex)
    raw_path = work_dir / "raw_payload.bin"
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_bytes(raw)
    seed = work_dir / "seed.sfuz"
    make_sfuz_seed(seed, raw_hex, case_name, tags=["rfuzz", "linknan-vcs"])
    return seed, raw
