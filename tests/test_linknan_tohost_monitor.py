from __future__ import annotations

import struct
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from linknan.vcs import (  # noqa: E402
    DEFAULT_TOHOST_ADDR,
    read_elf_symbol,
    resolve_tohost_addr,
    scan_vcs_logs,
)

REAL_RISCV_TEST = Path("/nfs/home/yangkefan/riscv-tests/isa/rv64ui-p-add")


def _make_elf64(symbols: dict[str, int]) -> bytes:
    """Build a minimal little-endian ELF64 with a SYMTAB + STRTAB.

    Enough structure for read_elf_symbol to resolve the given symbols; not a
    loadable image. Layout: [ehdr][symtab][strtab][shdr x3].
    """
    ehdr_size = 64
    sym_entsize = 24
    # String table: leading NUL, then each name NUL-terminated.
    names = list(symbols.keys())
    strtab = b"\x00"
    name_off: dict[str, int] = {}
    for n in names:
        name_off[n] = len(strtab)
        strtab += n.encode("utf-8") + b"\x00"
    # Symbol table: index 0 is the reserved null symbol.
    symtab = b"\x00" * sym_entsize
    for n in names:
        st_name = name_off[n]
        st_info = 0
        st_other = 0
        st_shndx = 1
        st_value = symbols[n]
        st_size = 0
        symtab += struct.pack("<IBBHQQ", st_name, st_info, st_other, st_shndx, st_value, st_size)

    symtab_off = ehdr_size
    strtab_off = symtab_off + len(symtab)
    shoff = strtab_off + len(strtab)
    shentsize = 64
    shnum = 3
    strtab_idx = 2

    def shdr(sh_name, sh_type, sh_offset, sh_size, sh_link, sh_entsize):
        return struct.pack(
            "<IIQQQQIIQQ",
            sh_name, sh_type, 0, 0, sh_offset, sh_size, sh_link, 0, 0, sh_entsize
        )

    sh_null = shdr(0, 0, 0, 0, 0, 0)
    sh_symtab = shdr(0, 2, symtab_off, len(symtab), strtab_idx, sym_entsize)  # SHT_SYMTAB
    sh_strtab = shdr(0, 3, strtab_off, len(strtab), 0, 0)  # SHT_STRTAB

    ehdr = bytearray(ehdr_size)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 2  # ELFCLASS64
    ehdr[5] = 1  # ELFDATA2LSB
    ehdr[6] = 1  # version
    struct.pack_into("<H", ehdr, 0x10, 2)  # e_type ET_EXEC
    struct.pack_into("<H", ehdr, 0x12, 243)  # e_machine RISC-V
    struct.pack_into("<Q", ehdr, 0x28, shoff)  # e_shoff
    struct.pack_into("<H", ehdr, 0x3A, shentsize)  # e_shentsize
    struct.pack_into("<H", ehdr, 0x3C, shnum)  # e_shnum
    struct.pack_into("<H", ehdr, 0x3E, strtab_idx)  # e_shstrndx

    return bytes(ehdr) + symtab + strtab + sh_null + sh_symtab + sh_strtab


class ReadElfSymbolTests(unittest.TestCase):
    def test_reads_symbol_from_synthetic_elf(self) -> None:
        blob = _make_elf64({"tohost": 0x80001000, "fromhost": 0x80001040})
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=True) as f:
            f.write(blob)
            f.flush()
            p = Path(f.name)
            self.assertEqual(read_elf_symbol(p, "tohost"), 0x80001000)
            self.assertEqual(read_elf_symbol(p, "fromhost"), 0x80001040)
            self.assertIsNone(read_elf_symbol(p, "missing"))

    def test_non_elf_returns_none(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=True) as f:
            f.write(b"\x73\x00\x10\x00 not an elf")
            f.flush()
            self.assertIsNone(read_elf_symbol(Path(f.name), "tohost"))

    def test_missing_file_returns_none(self) -> None:
        self.assertIsNone(read_elf_symbol(Path("/no/such/file.elf"), "tohost"))

    @unittest.skipUnless(REAL_RISCV_TEST.is_file(), "real riscv-test corpus not present")
    def test_reads_tohost_from_real_riscv_test(self) -> None:
        self.assertEqual(read_elf_symbol(REAL_RISCV_TEST, "tohost"), 0x80001000)


class ResolveTohostAddrTests(unittest.TestCase):
    def test_off_disables(self) -> None:
        self.assertEqual(resolve_tohost_addr("off", []), 0)
        self.assertEqual(resolve_tohost_addr("none", []), 0)
        self.assertEqual(resolve_tohost_addr("0", []), 0)

    def test_explicit_literal(self) -> None:
        self.assertEqual(resolve_tohost_addr("0x80001000", []), 0x80001000)
        self.assertEqual(resolve_tohost_addr("2147487744", []), 0x80001000)

    def test_auto_reads_elf_symbol(self) -> None:
        blob = _make_elf64({"tohost": 0x80005000})
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=True) as f:
            f.write(blob)
            f.flush()
            self.assertEqual(resolve_tohost_addr("auto", [Path(f.name)]), 0x80005000)

    def test_auto_falls_back_to_default_for_elf_without_symbol(self) -> None:
        blob = _make_elf64({"fromhost": 0x80001040})
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=True) as f:
            f.write(blob)
            f.flush()
            self.assertEqual(resolve_tohost_addr("auto", [Path(f.name)]), DEFAULT_TOHOST_ADDR)

    def test_auto_off_when_no_elf_seed(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=True) as f:
            f.write(b"\x73\x00\x10\x00")
            f.flush()
            self.assertEqual(resolve_tohost_addr("auto", [Path(f.name)]), 0)


class ScanTohostExitTests(unittest.TestCase):
    def _scan(self, body: str):
        with tempfile.TemporaryDirectory() as tmp:
            run_log = Path(tmp) / "run.log"
            assert_log = Path(tmp) / "assert.log"
            run_log.write_text(body, encoding="utf-8")
            assert_log.write_text("", encoding="utf-8")
            return scan_vcs_logs(run_log, assert_log, None)

    def test_tohost_pass_exit(self) -> None:
        info = self._scan(
            "HIT GOOD TRAP at pc = 0x80000048 (tohost)\n"
            "SFUZZ_TOHOST_EXIT: core=0 code=0 pc=0x80000048\n"
        )
        self.assertTrue(info.tohost_exit_seen)
        self.assertEqual(info.tohost_exit_code, 0)
        self.assertTrue(info.good_trap_seen)
        self.assertFalse(info.bug_triggered)

    def test_tohost_fail_exit_is_not_a_bug(self) -> None:
        info = self._scan("SFUZZ_TOHOST_EXIT: core=0 code=7 pc=0x80000048\n")
        self.assertTrue(info.tohost_exit_seen)
        self.assertEqual(info.tohost_exit_code, 7)
        # A nonzero HTIF code is a workload result, not an infra/design bug.
        self.assertFalse(info.bug_triggered)

    def test_no_tohost_marker(self) -> None:
        info = self._scan("Using simulated 32768B flash\n")
        self.assertFalse(info.tohost_exit_seen)
        self.assertIsNone(info.tohost_exit_code)


if __name__ == "__main__":
    unittest.main()
