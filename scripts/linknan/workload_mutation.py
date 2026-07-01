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


@dataclass(frozen=True)
class ElfMutableRange:
    name: str
    offset: int
    size: int


ENTRY_GUARD_BYTES = 256
EXIT_GUARD_BYTES = 1024
RAW_MIN_MUTABLE_BYTES = 512
MIN_GUARDED_MUTABLE_BYTES = 16
SHT_NOBITS = 8
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
MUTABLE_SECTION_NAMES = {".sfuzz_mutable", ".data", ".sdata", ".rodata"}
NEVER_MUTATE_SECTION_NAMES = {".text", ".init", ".fini", ".tohost", ".riscv.attributes"}


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


def _read_c_string(data: bytes, offset: int, limit: int) -> str:
    if offset < 0 or offset >= limit or offset >= len(data):
        return ""
    end = offset
    max_end = min(limit, len(data))
    while end < max_end and data[end] != 0:
        end += 1
    return data[offset:end].decode("utf-8", errors="replace")


def elf_mutable_ranges(data: bytes) -> list[ElfMutableRange]:
    """Return ELF file ranges that can be mutated without breaking execution.

    Long-running LinkNan workloads often have a tiny executable PT_LOAD segment:
    one bit flip in the loop counter, branch, or good-trap tail can turn a valid
    seed into a 900s timeout. Prefer explicit non-executable data sections and
    replay when the workload does not expose such a section.
    """

    if len(data) < 64 or not is_elf_bytes(data):
        return []
    elf_class = data[4]
    endian = "<" if data[5] == 1 else ">"
    if elf_class not in {1, 2} or data[5] not in {1, 2}:
        return []
    try:
        if elf_class == 2:
            e_shoff = struct.unpack_from(endian + "Q", data, 0x28)[0]
            e_shentsize = struct.unpack_from(endian + "H", data, 0x3A)[0]
            e_shnum = struct.unpack_from(endian + "H", data, 0x3C)[0]
            e_shstrndx = struct.unpack_from(endian + "H", data, 0x3E)[0]
            sh_name_off, sh_type_off, sh_flags_off = 0x00, 0x04, 0x08
            sh_offset_off, sh_size_off = 0x18, 0x20
            flags_fmt, offset_fmt, size_fmt = "Q", "Q", "Q"
        else:
            e_shoff = struct.unpack_from(endian + "I", data, 0x20)[0]
            e_shentsize = struct.unpack_from(endian + "H", data, 0x2E)[0]
            e_shnum = struct.unpack_from(endian + "H", data, 0x30)[0]
            e_shstrndx = struct.unpack_from(endian + "H", data, 0x32)[0]
            sh_name_off, sh_type_off, sh_flags_off = 0x00, 0x04, 0x08
            sh_offset_off, sh_size_off = 0x10, 0x14
            flags_fmt, offset_fmt, size_fmt = "I", "I", "I"
        if e_shoff <= 0 or e_shentsize <= 0 or e_shnum <= 0 or e_shstrndx >= e_shnum:
            return []
        shstr = e_shoff + e_shstrndx * e_shentsize
        if shstr < 0 or shstr + e_shentsize > len(data):
            return []
        shstr_offset = struct.unpack_from(endian + offset_fmt, data, shstr + sh_offset_off)[0]
        shstr_size = struct.unpack_from(endian + size_fmt, data, shstr + sh_size_off)[0]
        shstr_limit = int(shstr_offset + shstr_size)
        ranges: list[ElfMutableRange] = []
        for index in range(e_shnum):
            sh = e_shoff + index * e_shentsize
            if sh < 0 or sh + e_shentsize > len(data):
                return []
            name_offset = struct.unpack_from(endian + "I", data, sh + sh_name_off)[0]
            sh_type = struct.unpack_from(endian + "I", data, sh + sh_type_off)[0]
            sh_flags = struct.unpack_from(endian + flags_fmt, data, sh + sh_flags_off)[0]
            sh_offset = struct.unpack_from(endian + offset_fmt, data, sh + sh_offset_off)[0]
            sh_size = struct.unpack_from(endian + size_fmt, data, sh + sh_size_off)[0]
            name = _read_c_string(data, int(shstr_offset + name_offset), shstr_limit)
            if not name or name in NEVER_MUTATE_SECTION_NAMES:
                continue
            if sh_type == SHT_NOBITS or sh_size <= 0:
                continue
            if sh_offset < 0 or sh_offset + sh_size > len(data):
                continue
            alloc_data = bool(sh_flags & SHF_ALLOC) and not bool(sh_flags & SHF_EXECINSTR)
            explicit_mutable = name in MUTABLE_SECTION_NAMES
            if not explicit_mutable and not (alloc_data and bool(sh_flags & SHF_WRITE)):
                continue
            ranges.append(ElfMutableRange(name, int(sh_offset), int(sh_size)))
    except (struct.error, ValueError, OverflowError):
        return []
    ranges.sort(key=lambda item: (0 if item.name == ".sfuzz_mutable" else 1, item.offset))
    return ranges


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


def mutate_elf_range_bytes(
    parent: bytes,
    rng: random.Random,
    budget: int,
    ranges: list[ElfMutableRange],
) -> tuple[bytes, str]:
    data = bytearray(parent)
    operations: list[str] = []
    for _ in range(max(1, budget)):
        selected = rng.choice(ranges)
        idx = selected.offset + rng.randrange(selected.size)
        op = rng.randrange(4)
        prefix = f"elf-section:{selected.name}"
        if op == 0:
            bit = rng.randrange(8)
            data[idx] ^= 1 << bit
            operations.append(f"{prefix}:bitflip[{idx}:{bit}]")
        elif op == 1:
            data[idx] = rng.randrange(256)
            operations.append(f"{prefix}:overwrite8[{idx}]")
        elif op == 2:
            delta = rng.choice([-35, -16, -1, 1, 16, 35])
            data[idx] = (data[idx] + delta) & 0xFF
            operations.append(f"{prefix}:arith8{delta:+d}[{idx}]")
        else:
            width = min(4, selected.size - (idx - selected.offset))
            value = int.from_bytes(data[idx : idx + width], "little")
            value ^= 1 << rng.randrange(width * 8)
            data[idx : idx + width] = value.to_bytes(width, "little")
            operations.append(f"{prefix}:wordbit[{idx}:{width}]")
    return bytes(data), ";".join(operations)


def _s_type_imm(word: int) -> int:
    imm = ((word >> 25) << 5) | ((word >> 7) & 0x1F)
    return imm - 0x1000 if imm & 0x800 else imm


def _set_i_type_imm(word: int, imm: int) -> int:
    return (word & 0x000FFFFF) | ((imm & 0xFFF) << 20)


def _set_s_type_imm(word: int, imm: int) -> int:
    imm12 = imm & 0xFFF
    return (word & ~0xFE000F80) | ((imm12 >> 5) << 25) | ((imm12 & 0x1F) << 7)


def _choose_aligned_offset(rng: random.Random, current: int) -> int:
    choices = [value for value in range(0, 128, 8) if value != current]
    return rng.choice(choices) if choices else current


def _mutate_semantic_instruction_word(word: int, rng: random.Random) -> tuple[int, str] | None:
    opcode = word & 0x7F
    rd = (word >> 7) & 0x1F
    funct3 = (word >> 12) & 0x7
    rs1 = (word >> 15) & 0x1F
    if opcode == 0x03 and funct3 == 0x3 and rs1 == 5:  # ld ..., imm(x5)
        imm = (word >> 20) & 0xFFF
        imm = imm - 0x1000 if imm & 0x800 else imm
        if 0 <= imm < 128:
            new_imm = _choose_aligned_offset(rng, imm)
            return _set_i_type_imm(word, new_imm), f"ld-imm:{imm}->{new_imm}"
    if opcode == 0x23 and funct3 == 0x3 and rs1 == 5:  # sd ..., imm(x5)
        imm = _s_type_imm(word)
        if 0 <= imm < 128:
            new_imm = _choose_aligned_offset(rng, imm)
            return _set_s_type_imm(word, new_imm), f"sd-imm:{imm}->{new_imm}"
    if opcode == 0x13 and funct3 == 0x0 and rd not in {0, 5, 28}:  # addi temp, ..., imm
        imm = (word >> 20) & 0xFFF
        imm = imm - 0x1000 if imm & 0x800 else imm
        delta = rng.choice([-2, -1, 1, 2])
        new_imm = max(-2048, min(2047, imm + delta))
        if new_imm != imm:
            return _set_i_type_imm(word, new_imm), f"addi-imm:{imm}->{new_imm}"
    return None


def mutate_elf_semantic_instructions(parent: bytes, rng: random.Random, budget: int) -> tuple[bytes, str] | None:
    segments = elf_load_segments(parent)
    if not segments:
        return None
    for seg in segments:
        if seg.filesz % 4 or seg.filesz > 2048:
            continue
        words = [struct.unpack_from("<I", parent, seg.offset + index)[0] for index in range(0, seg.filesz, 4)]
        try:
            finish_index = len(words) - 1 - list(reversed(words)).index(0x0005006B)
        except ValueError:
            continue
        tail_start = max(0, finish_index - 10)
        candidates: list[tuple[int, int, str]] = []
        for word_index in range(5, tail_start):
            mutation = _mutate_semantic_instruction_word(words[word_index], rng)
            if mutation is None:
                continue
            _new_word, operation = mutation
            candidates.append((word_index, words[word_index], operation.split(":", 1)[0]))
        if not candidates:
            continue
        data = bytearray(parent)
        operations: list[str] = []
        for _ in range(max(1, budget)):
            word_index, old_word, _kind = rng.choice(candidates)
            mutated = _mutate_semantic_instruction_word(old_word, rng)
            if mutated is None:
                continue
            new_word, operation = mutated
            byte_offset = seg.offset + word_index * 4
            struct.pack_into("<I", data, byte_offset, new_word)
            operations.append(f"elf-instruction-preserving:{operation}@{byte_offset}")
        if operations and bytes(data) != parent:
            return bytes(data), ";".join(operations)
    return None


def mutate_elf_load_bytes(parent: bytes, rng: random.Random, budget: int) -> tuple[bytes, str, str]:
    ranges = elf_mutable_ranges(parent)
    if ranges:
        child, mutation = mutate_elf_range_bytes(parent, rng, budget, ranges)
        return child, mutation, "elf-workload-mutable-section"
    instruction_mutation = mutate_elf_semantic_instructions(parent, rng, budget)
    if instruction_mutation is not None:
        child, mutation = instruction_mutation
        return child, mutation, "elf-workload-instruction-preserving"
    if not elf_load_segments(parent):
        return parent, "elf-no-load-segment-replay", "elf-workload-replay"
    return parent, "elf-preserve-no-mutable-section-replay", "elf-workload-replay"


def mutate_linknan_workload(parent: bytes, rng: random.Random, budget: int, max_input_bytes: int = 0) -> tuple[bytes, str, str]:
    if is_elf_bytes(parent):
        return mutate_elf_load_bytes(parent, rng, budget)
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
