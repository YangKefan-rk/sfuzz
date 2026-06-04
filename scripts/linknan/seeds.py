from __future__ import annotations

import struct
import subprocess
from collections import Counter
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


@dataclass(frozen=True)
class SeedMicroIR:
    instruction_counts: dict[str, int]
    event_plan: tuple[str, ...]
    group_affinity: dict[str, int]

    @property
    def target_trace(self) -> str:
        return ";".join(f"{group}:{weight}" for group, weight in sorted(self.group_affinity.items()))

    @property
    def event_trace(self) -> str:
        return ";".join(self.event_plan)


def parse_hex_blob(text: str) -> bytes:
    cleaned = text.strip().replace("_", "").replace(" ", "")
    if cleaned.startswith(("0x", "0X")):
        cleaned = cleaned[2:]
    if len(cleaned) % 2:
        raise ValueError(f"hex payload must contain an even number of digits: {text!r}")
    return bytes.fromhex(cleaned)


def iter_riscv_words(payload: bytes, max_words: int = 2048) -> Iterable[int]:
    word_count = min(len(payload) // 4, max_words)
    for index in range(word_count):
        yield int.from_bytes(payload[index * 4 : index * 4 + 4], "little")


def classify_riscv_word(word: int) -> str:
    opcode = word & 0x7F
    if opcode == 0x03:
        return "load"
    if opcode == 0x23:
        return "store"
    if opcode == 0x2F:
        return "amo"
    if opcode == 0x63:
        return "branch"
    if opcode in {0x67, 0x6F}:
        return "jump"
    if opcode == 0x0F:
        return "fence"
    if opcode == 0x73:
        funct12 = (word >> 20) & 0xFFF
        if funct12 in {0x000, 0x001}:
            return "trap"
        if funct12 in {0x102, 0x105, 0x302}:
            return "return"
        return "csr"
    if opcode in {0x13, 0x1B, 0x33, 0x3B}:
        return "alu"
    return "other"


def infer_seed_micro_ir(seed: SfuzSeed) -> SeedMicroIR:
    counts: Counter[str] = Counter()
    events: list[str] = []
    affinity: Counter[str] = Counter()

    for hart, payload in (("core0", seed.core0_prog), ("core1", seed.core1_prog)):
        if not payload:
            continue
        local_counts = Counter(classify_riscv_word(word) for word in iter_riscv_words(payload))
        counts.update({f"{hart}.{kind}": count for kind, count in local_counts.items() if count})
        if local_counts["load"] or local_counts["store"] or local_counts["amo"]:
            events.append(f"{hart}:memory_stream")
            affinity["memory_event"] += 3 + local_counts["load"] + local_counts["store"] + local_counts["amo"]
            affinity["ready_valid"] += 1
        if local_counts["branch"] or local_counts["jump"]:
            events.append(f"{hart}:control_redirect")
            affinity["branch_event"] += 2 + local_counts["branch"] + local_counts["jump"]
            affinity["control_event"] += 1
            affinity["mux"] += 1
        if local_counts["trap"] or local_counts["csr"] or local_counts["return"] or local_counts["fence"]:
            events.append(f"{hart}:privileged_exception")
            affinity["exception_event"] += 2 + local_counts["trap"] + local_counts["csr"] + local_counts["return"]
            affinity["control_event"] += 1
        if local_counts["amo"]:
            events.append(f"{hart}:atomic_resource")
            affinity["resource_event"] += 2 + local_counts["amo"]

    if seed.shared_mem_init:
        cacheline_bases = {base // 64 for base, _data in seed.shared_mem_init}
        events.append(f"shared:segments={len(seed.shared_mem_init)}")
        affinity["memory_event"] += 2 + len(seed.shared_mem_init)
        affinity["resource_event"] += 1
        if len(cacheline_bases) < len(seed.shared_mem_init):
            events.append("shared:cacheline_alias")
            affinity["queue_event"] += 2
            affinity["resource_event"] += 2

    if seed.interrupt_plan_raw:
        events.append(f"interrupt:events={len(seed.interrupt_plan_raw)}")
        affinity["exception_event"] += 3 + len(seed.interrupt_plan_raw)
        affinity["control_event"] += 2

    tag_text = " ".join([seed.name, seed.description, *seed.tags]).lower()
    for tag in seed.tags:
        key, sep, value = tag.partition(":")
        if not sep:
            continue
        if key.strip().lower() == "target":
            group = value.strip().lower().replace("-", "_").replace(".", "_")
            if group.startswith("sfuzz_"):
                affinity[group] += 8
        elif key.strip().lower() == "event":
            event = value.strip().lower().replace("-", "_")
            if any(word in event for word in ("amo", "lr_", "sc_")):
                affinity["sfuzz_atomic"] += 3
            if "fence" in event:
                affinity["sfuzz_fence"] += 3
            if any(word in event for word in ("replay", "violation", "forward")):
                affinity["sfuzz_lsq"] += 3
            if any(word in event for word in ("mshr", "miss", "bank_conflict")):
                affinity["sfuzz_dcache"] += 2
                affinity["sfuzz_resource"] += 2
            if any(word in event for word in ("probe", "release")):
                affinity["sfuzz_coherence"] += 3
            if any(word in event for word in ("trap", "exception")):
                affinity["sfuzz_exception"] += 2
            if "branch" in event or "redirect" in event:
                affinity["sfuzz_branch"] += 2
    keyword_groups = {
        "mmu": "memory_event",
        "tlb": "memory_event",
        "cache": "memory_event",
        "mshr": "resource_event",
        "branch": "branch_event",
        "redirect": "branch_event",
        "exception": "exception_event",
        "interrupt": "exception_event",
        "queue": "queue_event",
    }
    for keyword, group in keyword_groups.items():
        if keyword in tag_text:
            affinity[group] += 2

    if not affinity:
        events.append("core0:bootstrap")
        affinity["ready_valid"] += 1
        affinity["toggle"] += 1

    deduped_events: list[str] = []
    for event in events:
        if event not in deduped_events:
            deduped_events.append(event)

    return SeedMicroIR(
        instruction_counts=dict(sorted(counts.items())),
        event_plan=tuple(deduped_events),
        group_affinity=dict(sorted((group, max(1, weight)) for group, weight in affinity.items())),
    )


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
