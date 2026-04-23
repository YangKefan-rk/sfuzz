#!/usr/bin/env python3
import argparse
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

MAGIC = b"SFUZ"
VERSION = 1
PT_LOAD = 1
COPY_CHUNK = 1024 * 1024
U32_MAX = (1 << 32) - 1


def parse_hex_blob(text: str) -> bytes:
    cleaned = text.strip().replace("_", "").replace(" ", "")
    if cleaned.startswith(("0x", "0X")):
        cleaned = cleaned[2:]
    if len(cleaned) % 2 != 0:
        raise ValueError(f"hex payload must contain an even number of digits: {text!r}")
    return bytes.fromhex(cleaned)


def checked_u32(value: int, label: str) -> int:
    if not 0 <= value <= U32_MAX:
        raise ValueError(f"{label} does not fit in the SFUZ v1 u32 field: {value}")
    return value


def write_u16(output: BinaryIO, value: int) -> None:
    output.write(struct.pack("<H", value))


def write_u32(output: BinaryIO, value: int, label: str) -> None:
    output.write(struct.pack("<I", checked_u32(value, label)))


def write_u64(output: BinaryIO, value: int) -> None:
    output.write(struct.pack("<Q", value))


def write_zeroes(output: BinaryIO, count: int) -> None:
    if count < 0:
        raise ValueError(f"cannot write a negative number of zero bytes: {count}")
    if count == 0:
        return
    chunk = b"\0" * min(COPY_CHUNK, count)
    remaining = count
    while remaining > 0:
        piece = chunk if remaining >= len(chunk) else chunk[:remaining]
        output.write(piece)
        remaining -= len(piece)


def copy_exact(input_file: BinaryIO, output_file: BinaryIO, size: int) -> None:
    remaining = size
    while remaining > 0:
        chunk = input_file.read(min(COPY_CHUNK, remaining))
        if not chunk:
            raise ValueError(f"unexpected end of file while copying {size} bytes")
        output_file.write(chunk)
        remaining -= len(chunk)


@dataclass(frozen=True)
class LoadSegment:
    load_addr: int
    file_offset: int
    file_size: int
    mem_size: int


class BlobSource:
    def __init__(self, size: int, description: str) -> None:
        self.size = checked_u32(size, f"{description} size")
        self.description = description

    def write_payload(self, output: BinaryIO) -> None:
        raise NotImplementedError


class InlineBlobSource(BlobSource):
    def __init__(self, data: bytes, description: str) -> None:
        super().__init__(len(data), description)
        self.data = data

    def write_payload(self, output: BinaryIO) -> None:
        output.write(self.data)


class FileBlobSource(BlobSource):
    def __init__(self, path: Path, description: str) -> None:
        self.path = path
        try:
            size = path.stat().st_size
        except FileNotFoundError as exc:
            raise ValueError(f"{description} file does not exist: {path}") from exc
        super().__init__(size, description)

    def write_payload(self, output: BinaryIO) -> None:
        with self.path.open("rb") as input_file:
            copy_exact(input_file, output, self.size)


class ElfBlobSource(BlobSource):
    def __init__(self, path: Path, description: str) -> None:
        self.path = path
        self.base_addr, self.segments, size = parse_elf_load_segments(path)
        super().__init__(size, description)

    def write_payload(self, output: BinaryIO) -> None:
        cursor = 0
        with self.path.open("rb") as input_file:
            for segment in self.segments:
                segment_start = segment.load_addr - self.base_addr
                if segment_start < cursor:
                    raise ValueError(
                        f"{self.description} contains overlapping PT_LOAD segments, which cannot be normalized"
                    )
                write_zeroes(output, segment_start - cursor)
                input_file.seek(segment.file_offset)
                copy_exact(input_file, output, segment.file_size)
                write_zeroes(output, segment.mem_size - segment.file_size)
                cursor = segment_start + segment.mem_size
            write_zeroes(output, self.size - cursor)


def parse_elf_load_segments(path: Path) -> tuple[int, list[LoadSegment], int]:
    with path.open("rb") as input_file:
        ident = input_file.read(16)
        if len(ident) != 16:
            raise ValueError(f"ELF file is too short: {path}")
        if ident[:4] != b"ELF":
            raise ValueError(f"file is not an ELF binary: {path}")

        elf_class = ident[4]
        endianness = ident[5]
        if elf_class == 1:
            header_format = select_struct_format(endianness, "HHIIIIIHHHHHH")
            program_header_format = select_struct_format(endianness, "IIIIIIII")
            is_64_bit = False
        elif elf_class == 2:
            header_format = select_struct_format(endianness, "HHIQQQIHHHHHH")
            program_header_format = select_struct_format(endianness, "IIQQQQQQ")
            is_64_bit = True
        else:
            raise ValueError(f"unsupported ELF class {elf_class} in {path}")

        header_size = struct.calcsize(header_format)
        header = input_file.read(header_size)
        if len(header) != header_size:
            raise ValueError(f"failed to read ELF header from {path}")
        fields = struct.unpack(header_format, header)
        e_phoff = fields[4]
        e_phentsize = fields[8]
        e_phnum = fields[9]
        if e_phnum == 0:
            raise ValueError(f"ELF file has no program headers: {path}")

        expected_phdr_size = struct.calcsize(program_header_format)
        if e_phentsize < expected_phdr_size:
            raise ValueError(
                f"ELF program header size {e_phentsize} is smaller than expected {expected_phdr_size}: {path}"
            )

        segments: list[LoadSegment] = []
        for index in range(e_phnum):
            input_file.seek(e_phoff + index * e_phentsize)
            raw_header = input_file.read(e_phentsize)
            if len(raw_header) != e_phentsize:
                raise ValueError(f"failed to read program header {index} from {path}")
            program_header = raw_header[:expected_phdr_size]
            if is_64_bit:
                p_type, _flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, _align = struct.unpack(
                    program_header_format, program_header
                )
            else:
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, _flags, _align = struct.unpack(
                    program_header_format, program_header
                )
            if p_type != PT_LOAD or p_memsz == 0:
                continue
            if p_filesz > p_memsz:
                raise ValueError(f"ELF PT_LOAD segment has filesz > memsz in {path}")
            load_addr = p_paddr if p_paddr != 0 else p_vaddr
            segments.append(
                LoadSegment(
                    load_addr=load_addr,
                    file_offset=p_offset,
                    file_size=p_filesz,
                    mem_size=p_memsz,
                )
            )

    if not segments:
        raise ValueError(f"ELF file contains no loadable PT_LOAD segments: {path}")

    segments.sort(key=lambda segment: segment.load_addr)
    base_addr = segments[0].load_addr
    end_addr = 0
    cursor = 0
    for segment in segments:
        segment_start = segment.load_addr - base_addr
        if segment_start < cursor:
            raise ValueError(f"ELF file contains overlapping PT_LOAD segments: {path}")
        cursor = segment_start + segment.mem_size
        end_addr = max(end_addr, segment.load_addr + segment.mem_size)

    normalized_size = end_addr - base_addr
    checked_u32(normalized_size, f"normalized ELF image for {path}")
    return base_addr, segments, normalized_size


def select_struct_format(endianness: int, payload: str) -> str:
    if endianness == 1:
        return "<" + payload
    if endianness == 2:
        return ">" + payload
    raise ValueError(f"unsupported ELF endianness tag: {endianness}")


def parse_shared(entry: str) -> tuple[int, BlobSource]:
    if ":" not in entry:
        raise ValueError(f"shared segment must be BASE:FILE, got {entry!r}")
    base_text, file_text = entry.split(":", 1)
    base_addr = int(base_text, 0)
    blob = FileBlobSource(Path(file_text), f"shared segment {file_text}")
    return base_addr, blob


def load_program_source(
    bin_path: str | None,
    hex_blob: str | None,
    elf_path: str | None,
    label: str,
) -> BlobSource:
    selected = [value is not None for value in (bin_path, hex_blob, elf_path)]
    if sum(selected) > 1:
        raise ValueError(f"choose only one of --{label}-bin, --{label}-hex, or --{label}-elf")
    if bin_path:
        return FileBlobSource(Path(bin_path), f"{label} payload")
    if hex_blob:
        return InlineBlobSource(parse_hex_blob(hex_blob), f"{label} payload")
    if elf_path:
        return ElfBlobSource(Path(elf_path), f"{label} ELF payload")
    return InlineBlobSource(b"", f"{label} payload")


def write_blob(output: BinaryIO, blob: BlobSource, label: str) -> None:
    write_u32(output, blob.size, f"{label} length")
    blob.write_payload(output)


def write_string(output: BinaryIO, text: str, label: str) -> None:
    encoded = text.encode("utf-8")
    write_blob(output, InlineBlobSource(encoded, label), label)


def write_seed(output_path: Path, args: argparse.Namespace) -> int:
    core0_prog = load_program_source(args.core0_bin, args.core0_hex, args.core0_elf, "core0")
    core1_prog = load_program_source(args.core1_bin, args.core1_hex, args.core1_elf, "core1")
    shared_segments = [parse_shared(item) for item in args.shared]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as output:
        output.write(MAGIC)
        write_u16(output, VERSION)
        write_u16(output, 0)
        write_blob(output, core0_prog, "core0")
        write_blob(output, core1_prog, "core1")
        write_u32(output, len(shared_segments), "shared segment count")
        for base_addr, blob in shared_segments:
            write_u64(output, base_addr)
            write_blob(output, blob, f"shared segment at 0x{base_addr:x}")
        write_u32(output, 0, "interrupt count")
        write_string(output, args.name, "seed name")
        write_string(output, args.description, "seed description")
        write_u32(output, len(args.tag), "tag count")
        for index, tag in enumerate(args.tag):
            write_string(output, tag, f"tag {index}")

    return output_path.stat().st_size


def main() -> int:
    parser = argparse.ArgumentParser(description="Build an SFUZ structured-seed container")
    parser.add_argument("-o", "--output", required=True, help="output SFUZ file")
    parser.add_argument("--core0-bin", help="core0 program image file")
    parser.add_argument("--core0-hex", help="core0 program bytes in hex")
    parser.add_argument("--core0-elf", help="normalize a core0 ELF into a flat SFUZ payload")
    parser.add_argument("--core1-bin", help="core1 program image file")
    parser.add_argument("--core1-hex", help="core1 program bytes in hex")
    parser.add_argument("--core1-elf", help="normalize a core1 ELF into a flat SFUZ payload")
    parser.add_argument(
        "--shared",
        action="append",
        default=[],
        metavar="BASE:FILE",
        help="append one shared-memory segment from FILE at BASE",
    )
    parser.add_argument("--name", default="", help="seed metadata name")
    parser.add_argument("--description", default="", help="seed metadata description")
    parser.add_argument("--tag", action="append", default=[], help="seed metadata tag")
    args = parser.parse_args()

    size = write_seed(Path(args.output), args)
    print(Path(args.output))
    print(size)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
