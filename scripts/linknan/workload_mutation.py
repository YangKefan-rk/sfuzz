from __future__ import annotations

import random
import struct
from dataclasses import dataclass
from pathlib import Path


ELF_MAGIC = b"\x7fELF"
PT_LOAD = 1
LOADER_ASSERT_MARKERS = (
    "elfloader.cpp",
    "Assertion",
)


@dataclass(frozen=True)
class ElfLoadSegment:
    offset: int
    filesz: int


ENTRY_GUARD_BYTES = 256
EXIT_GUARD_BYTES = 1024
RAW_MIN_MUTABLE_BYTES = 512
MIN_GUARDED_MUTABLE_BYTES = 16


def is_elf_bytes(data: bytes) -> bool:
    return data.startswith(ELF_MAGIC)


def elf_load_segments(data: bytes) -> list[ElfLoadSegment]:
    """Return byte ranges for ELF PT_LOAD file contents.

    Fuzzing LinkNan workload ELF headers corrupts the C++ ELF loader before the
    DUT runs. Keep ELF metadata stable and mutate only bytes that are actually
    loaded into simulated memory.
    """

    if len(data) < 64 or not is_elf_bytes(data):
        return []
    elf_class = data[4]
    endian = "<" if data[5] == 1 else ">"
    if elf_class not in {1, 2} or data[5] not in {1, 2}:
        return []
    try:
        if elf_class == 2:
            e_phoff = struct.unpack_from(endian + "Q", data, 0x20)[0]
            e_phentsize = struct.unpack_from(endian + "H", data, 0x36)[0]
            e_phnum = struct.unpack_from(endian + "H", data, 0x38)[0]
            p_type_off, p_offset_off, p_filesz_off = 0x00, 0x08, 0x20
            p_offset_fmt, p_filesz_fmt = "Q", "Q"
        else:
            e_phoff = struct.unpack_from(endian + "I", data, 0x1C)[0]
            e_phentsize = struct.unpack_from(endian + "H", data, 0x2A)[0]
            e_phnum = struct.unpack_from(endian + "H", data, 0x2C)[0]
            p_type_off, p_offset_off, p_filesz_off = 0x00, 0x04, 0x10
            p_offset_fmt, p_filesz_fmt = "I", "I"
        if e_phoff <= 0 or e_phentsize <= 0 or e_phnum <= 0:
            return []
        segments: list[ElfLoadSegment] = []
        for index in range(e_phnum):
            ph = e_phoff + index * e_phentsize
            if ph < 0 or ph + e_phentsize > len(data):
                return []
            p_type = struct.unpack_from(endian + "I", data, ph + p_type_off)[0]
            if p_type != PT_LOAD:
                continue
            p_offset = struct.unpack_from(endian + p_offset_fmt, data, ph + p_offset_off)[0]
            p_filesz = struct.unpack_from(endian + p_filesz_fmt, data, ph + p_filesz_off)[0]
            if p_filesz <= 0:
                continue
            if p_offset < 0 or p_offset + p_filesz > len(data):
                return []
            segments.append(ElfLoadSegment(int(p_offset), int(p_filesz)))
    except (struct.error, ValueError, OverflowError):
        return []
    return segments


def guarded_payload_window(size: int, *, raw_flat_image: bool) -> tuple[int, int] | None:
    if size <= 0:
        return None
    if raw_flat_image and size < RAW_MIN_MUTABLE_BYTES:
        return None
    if size <= MIN_GUARDED_MUTABLE_BYTES:
        return (0, size)

    max_guard = max(0, (size - MIN_GUARDED_MUTABLE_BYTES) // 4)
    head = min(ENTRY_GUARD_BYTES, max_guard)
    tail = min(EXIT_GUARD_BYTES, max_guard)
    if head + tail >= size:
        return (0, size)
    return (head, size - tail)


def choose_index_in_window(rng: random.Random, base: int, size: int, *, width: int = 1) -> int | None:
    window = guarded_payload_window(size, raw_flat_image=False)
    if window is None:
        return None
    start, end = window
    end = max(start, end - max(0, width - 1))
    if end <= start:
        return None
    return base + rng.randrange(start, end)


def mutate_raw_bytes(parent: bytes, rng: random.Random, budget: int, max_input_bytes: int = 0) -> tuple[bytes, str]:
    data = bytearray(parent or b"\x00")
    window = guarded_payload_window(len(data), raw_flat_image=True)
    if window is None:
        return bytes(data), "raw-preserve-small-workload-replay"
    start, end = window
    operations: list[str] = []
    for _ in range(max(1, budget)):
        op = rng.randrange(4)
        idx = rng.randrange(start, end)
        if op == 0:
            bit = rng.randrange(8)
            data[idx] ^= 1 << bit
            operations.append(f"guarded-bitflip[{idx}:{bit}]")
        elif op == 1:
            data[idx] = rng.randrange(256)
            operations.append(f"guarded-overwrite8[{idx}]")
        elif op == 2:
            delta = rng.choice([-35, -16, -1, 1, 16, 35])
            data[idx] = (data[idx] + delta) & 0xFF
            operations.append(f"guarded-arith8{delta:+d}[{idx}]")
        else:
            width = min(4, len(data))
            idx = rng.randrange(start, max(start + 1, end - width + 1))
            value = int.from_bytes(data[idx : idx + width], "little")
            value ^= 1 << rng.randrange(width * 8)
            data[idx : idx + width] = value.to_bytes(width, "little")
            operations.append(f"guarded-wordbit[{idx}:{width}]")
    if not data:
        data.append(0)
    if max_input_bytes > 0 and len(data) > max_input_bytes:
        del data[max_input_bytes:]
        operations.append(f"truncate={max_input_bytes}")
    return bytes(data), ";".join(operations)


def mutate_elf_load_bytes(parent: bytes, rng: random.Random, budget: int) -> tuple[bytes, str]:
    data = bytearray(parent)
    segments = elf_load_segments(parent)
    if not segments:
        return bytes(data), "elf-no-load-segment"
    operations: list[str] = []
    for _ in range(max(1, budget)):
        seg = rng.choice(segments)
        idx = choose_index_in_window(rng, seg.offset, seg.filesz)
        if idx is None:
            operations.append("elf-load-preserve-small-segment-replay")
            continue
        op = rng.randrange(4)
        if op == 0:
            bit = rng.randrange(8)
            data[idx] ^= 1 << bit
            operations.append(f"elf-load-guarded-bitflip[{idx}:{bit}]")
        elif op == 1:
            data[idx] = rng.randrange(256)
            operations.append(f"elf-load-guarded-overwrite8[{idx}]")
        elif op == 2:
            delta = rng.choice([-35, -16, -1, 1, 16, 35])
            data[idx] = (data[idx] + delta) & 0xFF
            operations.append(f"elf-load-guarded-arith8{delta:+d}[{idx}]")
        else:
            width = min(4, seg.filesz - (idx - seg.offset))
            value = int.from_bytes(data[idx : idx + width], "little")
            value ^= 1 << rng.randrange(width * 8)
            data[idx : idx + width] = value.to_bytes(width, "little")
            operations.append(f"elf-load-guarded-wordbit[{idx}:{width}]")
    return bytes(data), ";".join(operations)


def mutate_linknan_workload(parent: bytes, rng: random.Random, budget: int, max_input_bytes: int = 0) -> tuple[bytes, str, str]:
    if is_elf_bytes(parent):
        child, mutation = mutate_elf_load_bytes(parent, rng, budget)
        return child, mutation, "elf-workload-load-segment"
    child, mutation = mutate_raw_bytes(parent, rng, budget, max_input_bytes=max_input_bytes)
    return child, mutation, "binary-workload-raw-bytes"


def mutate_linknan_workload_file(
    parent: Path,
    output: Path,
    rng: random.Random,
    budget: int,
    max_input_bytes: int = 0,
) -> tuple[str, str]:
    child, mutation, model = mutate_linknan_workload(parent.read_bytes(), rng, budget, max_input_bytes=max_input_bytes)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(child)
    return mutation, model


def linknan_loader_assertion(assert_log: Path) -> bool:
    try:
        text = assert_log.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return all(marker in text for marker in LOADER_ASSERT_MARKERS)
