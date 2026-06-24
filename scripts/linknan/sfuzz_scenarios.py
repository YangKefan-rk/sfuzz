from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .common import slugify
from .seeds import SfuzSeed, write_sfuz_seed


PMEM_BASE = 0x80000000
DEFAULT_SHARED_BASE = PMEM_BASE + 0x4000
DEFAULT_CACHELINE_BYTES = 64
EXCEPTION_HANDLER_OFFSET = 0x100

SCENARIO_FAMILIES = (
    "memory_alias",
    "cacheline_conflict",
    "load_store_dependency",
    "store_load_reordering",
    "amo_contention",
    "lrsc_success_fail",
    "fence_ordering",
    "branch_flush_memory",
    "exception_during_memory",
    "tlb_refill_memory",
    "mshr_pressure",
    "queue_backpressure",
)

SEMANTIC_OPERATORS = (
    "insert_load_store_pair",
    "create_same_cacheline_alias",
    "create_cross_cacheline_alias",
    "create_store_load_dependency",
    "create_load_use_dependency",
    "insert_branch_around_memory",
    "insert_exception_near_memory",
    "insert_tlb_pressure_sequence",
    "insert_amo_sequence",
    "insert_lrsc_pair",
    "force_sc_fail_window",
    "insert_fence_rw_rw",
    "insert_fence_before_after_amo",
    "insert_multicore_pingpong",
    "increase_mshr_pressure",
    "increase_store_buffer_pressure",
    "increase_replay_pressure",
)

GROUP_OPERATOR_HINTS = {
    "sfuzz_atomic": ("insert_amo_sequence", "insert_lrsc_pair", "force_sc_fail_window", "insert_fence_before_after_amo"),
    "sfuzz_fence": ("insert_fence_rw_rw", "insert_fence_before_after_amo"),
    "sfuzz_lsq": ("create_store_load_dependency", "create_load_use_dependency", "increase_replay_pressure"),
    "sfuzz_coherence": ("insert_multicore_pingpong", "create_same_cacheline_alias", "create_cross_cacheline_alias"),
    "sfuzz_mmu": ("insert_tlb_pressure_sequence",),
    "sfuzz_dcache": ("create_same_cacheline_alias", "create_cross_cacheline_alias", "increase_mshr_pressure"),
    "sfuzz_exception": ("insert_exception_near_memory",),
    "sfuzz_branch": ("insert_branch_around_memory",),
    "sfuzz_resource": ("increase_mshr_pressure", "increase_store_buffer_pressure", "increase_replay_pressure"),
    "memory_event": ("insert_load_store_pair", "create_store_load_dependency", "increase_mshr_pressure"),
    "branch_event": ("insert_branch_around_memory",),
    "exception_event": ("insert_exception_near_memory",),
    "resource_event": ("increase_mshr_pressure", "increase_store_buffer_pressure"),
}

OPERATOR_FAMILY = {
    "insert_load_store_pair": "memory_alias",
    "create_same_cacheline_alias": "cacheline_conflict",
    "create_cross_cacheline_alias": "cacheline_conflict",
    "create_store_load_dependency": "load_store_dependency",
    "create_load_use_dependency": "load_store_dependency",
    "insert_branch_around_memory": "branch_flush_memory",
    "insert_exception_near_memory": "exception_during_memory",
    "insert_tlb_pressure_sequence": "tlb_refill_memory",
    "insert_amo_sequence": "amo_contention",
    "insert_lrsc_pair": "lrsc_success_fail",
    "force_sc_fail_window": "lrsc_success_fail",
    "insert_fence_rw_rw": "fence_ordering",
    "insert_fence_before_after_amo": "fence_ordering",
    "insert_multicore_pingpong": "cacheline_conflict",
    "increase_mshr_pressure": "mshr_pressure",
    "increase_store_buffer_pressure": "queue_backpressure",
    "increase_replay_pressure": "load_store_dependency",
}

FAMILY_DEFAULT_OPERATOR = {
    "memory_alias": "insert_load_store_pair",
    "cacheline_conflict": "create_same_cacheline_alias",
    "load_store_dependency": "create_store_load_dependency",
    "store_load_reordering": "insert_fence_rw_rw",
    "amo_contention": "insert_amo_sequence",
    "lrsc_success_fail": "insert_lrsc_pair",
    "fence_ordering": "insert_fence_rw_rw",
    "branch_flush_memory": "insert_branch_around_memory",
    "exception_during_memory": "insert_exception_near_memory",
    "tlb_refill_memory": "insert_tlb_pressure_sequence",
    "mshr_pressure": "increase_mshr_pressure",
    "queue_backpressure": "increase_store_buffer_pressure",
}


@dataclass(frozen=True)
class EncodedInstruction:
    asm: str
    word: int
    role: str = ""

    def to_bytes(self) -> bytes:
        return self.word.to_bytes(4, "little")


@dataclass(frozen=True)
class InstructionBlock:
    core: int
    label: str
    instructions: tuple[EncodedInstruction, ...]

    def payload(self) -> bytes:
        return b"".join(inst.to_bytes() for inst in self.instructions)


@dataclass(frozen=True)
class SharedRegion:
    name: str
    base: int
    size: int
    init: bytes


@dataclass(frozen=True)
class ScenarioIR:
    scenario_id: str
    scenario_family: str
    target_groups: tuple[str, ...]
    cores: tuple[int, ...]
    shared_regions: tuple[SharedRegion, ...]
    instruction_blocks: tuple[InstructionBlock, ...]
    synchronization_points: tuple[str, ...]
    expected_micro_events: tuple[str, ...]
    semantic_operator: str
    requires_core1_handoff: bool = False
    core1_handoff_enabled: bool = False
    runtime_profile: str = "short"
    stress_iterations: int = 0
    target_min_wall_time_sec: int = 0

    @property
    def formal_multicore_result(self) -> bool:
        return not self.requires_core1_handoff or self.core1_handoff_enabled

    def core_payload(self, core: int) -> bytes:
        return b"".join(block.payload() for block in self.instruction_blocks if block.core == core)

    def assembly(self) -> str:
        lines = [
            "    .option norvc",
            "    .section .text",
            "    .globl _start",
            "_start:",
        ]
        for block in self.instruction_blocks:
            if block.core == 0:
                lines.append(f"{block.label}:")
                lines.extend(f"    .word 0x{inst.word:08x} # {inst.asm}" for inst in block.instructions)
        core1_blocks = [block for block in self.instruction_blocks if block.core == 1]
        if core1_blocks:
            lines.extend(["", "    .section .text.core1", "core1_start:"])
            for block in core1_blocks:
                lines.append(f"{block.label}:")
                lines.extend(f"    .word 0x{inst.word:08x} # {inst.asm}" for inst in block.instructions)
        return "\n".join(lines) + "\n"

    def metadata(self) -> dict[str, object]:
        return {
            "scenario_id": self.scenario_id,
            "scenario_family": self.scenario_family,
            "semantic_operator": self.semantic_operator,
            "target_groups": list(self.target_groups),
            "cores": list(self.cores),
            "shared_regions": [
                {"name": region.name, "base": region.base, "size": region.size} for region in self.shared_regions
            ],
            "synchronization_points": list(self.synchronization_points),
            "expected_micro_events": list(self.expected_micro_events),
            "requires_core1_handoff": self.requires_core1_handoff,
            "core1_handoff_enabled": self.core1_handoff_enabled,
            "formal_multicore_result": self.formal_multicore_result,
            "runtime_profile": self.runtime_profile,
            "stress_iterations": self.stress_iterations,
            "target_min_wall_time_sec": self.target_min_wall_time_sec,
        }


def _check_signed(value: int, bits: int, label: str) -> int:
    lo = -(1 << (bits - 1))
    hi = (1 << (bits - 1)) - 1
    if not lo <= value <= hi:
        raise ValueError(f"{label} immediate {value} does not fit signed {bits} bits")
    return value & ((1 << bits) - 1)


def _check_unsigned(value: int, bits: int, label: str) -> int:
    if not 0 <= value < (1 << bits):
        raise ValueError(f"{label} immediate {value} does not fit unsigned {bits} bits")
    return value


def r_type(opcode: int, rd: int, funct3: int, rs1: int, rs2: int, funct7: int) -> int:
    return ((funct7 & 0x7F) << 25) | ((rs2 & 0x1F) << 20) | ((rs1 & 0x1F) << 15) | ((funct3 & 7) << 12) | ((rd & 0x1F) << 7) | (opcode & 0x7F)


def i_type(opcode: int, rd: int, funct3: int, rs1: int, imm: int) -> int:
    imm12 = _check_signed(imm, 12, "I-type")
    return (imm12 << 20) | ((rs1 & 0x1F) << 15) | ((funct3 & 7) << 12) | ((rd & 0x1F) << 7) | (opcode & 0x7F)


def s_type(opcode: int, funct3: int, rs1: int, rs2: int, imm: int) -> int:
    imm12 = _check_signed(imm, 12, "S-type")
    return ((imm12 >> 5) << 25) | ((rs2 & 0x1F) << 20) | ((rs1 & 0x1F) << 15) | ((funct3 & 7) << 12) | ((imm12 & 0x1F) << 7) | (opcode & 0x7F)


def b_type(opcode: int, funct3: int, rs1: int, rs2: int, offset: int) -> int:
    if offset % 2:
        raise ValueError(f"branch offset must be 2-byte aligned: {offset}")
    imm = _check_signed(offset, 13, "B-type")
    return (
        ((imm >> 12) & 1) << 31
        | ((imm >> 5) & 0x3F) << 25
        | ((rs2 & 0x1F) << 20)
        | ((rs1 & 0x1F) << 15)
        | ((funct3 & 7) << 12)
        | ((imm >> 1) & 0xF) << 8
        | ((imm >> 11) & 1) << 7
        | (opcode & 0x7F)
    )


def u_type(opcode: int, rd: int, imm20: int) -> int:
    return (_check_unsigned(imm20, 20, "U-type") << 12) | ((rd & 0x1F) << 7) | (opcode & 0x7F)


def amo_type(rd: int, rs1: int, rs2: int, funct5: int, aq: bool = False, rl: bool = False) -> int:
    return (
        ((funct5 & 0x1F) << 27)
        | ((1 if aq else 0) << 26)
        | ((1 if rl else 0) << 25)
        | ((rs2 & 0x1F) << 20)
        | ((rs1 & 0x1F) << 15)
        | (0x3 << 12)
        | ((rd & 0x1F) << 7)
        | 0x2F
    )


def inst(asm: str, word: int, role: str = "") -> EncodedInstruction:
    return EncodedInstruction(asm, word & 0xFFFFFFFF, role)


def nop(role: str = "pad") -> EncodedInstruction:
    return addi(0, 0, 0, role)


def addi(rd: int, rs1: int, imm: int, role: str = "") -> EncodedInstruction:
    return inst(f"addi x{rd}, x{rs1}, {imm}", i_type(0x13, rd, 0, rs1, imm), role)


def slli(rd: int, rs1: int, shamt: int, role: str = "") -> EncodedInstruction:
    _check_unsigned(shamt, 6, "slli")
    return inst(f"slli x{rd}, x{rs1}, {shamt}", i_type(0x13, rd, 1, rs1, shamt), role)


def lui(rd: int, imm20: int, role: str = "") -> EncodedInstruction:
    return inst(f"lui x{rd}, 0x{imm20:x}", u_type(0x37, rd, imm20), role)


def add(rd: int, rs1: int, rs2: int, role: str = "") -> EncodedInstruction:
    return inst(f"add x{rd}, x{rs1}, x{rs2}", r_type(0x33, rd, 0, rs1, rs2, 0), role)


def ld(rd: int, rs1: int, imm: int = 0, role: str = "load") -> EncodedInstruction:
    return inst(f"ld x{rd}, {imm}(x{rs1})", i_type(0x03, rd, 3, rs1, imm), role)


def sd(rs2: int, rs1: int, imm: int = 0, role: str = "store") -> EncodedInstruction:
    return inst(f"sd x{rs2}, {imm}(x{rs1})", s_type(0x23, 3, rs1, rs2, imm), role)


def beq(rs1: int, rs2: int, offset: int, role: str = "branch") -> EncodedInstruction:
    return inst(f"beq x{rs1}, x{rs2}, {offset:+}", b_type(0x63, 0, rs1, rs2, offset), role)


def bne(rs1: int, rs2: int, offset: int, role: str = "branch") -> EncodedInstruction:
    return inst(f"bne x{rs1}, x{rs2}, {offset:+}", b_type(0x63, 1, rs1, rs2, offset), role)


def fence_rw_rw(role: str = "fence") -> EncodedInstruction:
    return inst("fence rw, rw", i_type(0x0F, 0, 0, 0, 0x33), role)


def sfence_vma(role: str = "mmu") -> EncodedInstruction:
    return inst("sfence.vma x0, x0", 0x12000073, role)


def csrr(rd: int, csr: int, role: str = "csr") -> EncodedInstruction:
    word = ((csr & 0xFFF) << 20) | (0 << 15) | (0x2 << 12) | ((rd & 0x1F) << 7) | 0x73
    return inst(f"csrr x{rd}, 0x{csr:x}", word, role)


def csrw(csr: int, rs1: int, role: str = "csr") -> EncodedInstruction:
    word = ((csr & 0xFFF) << 20) | ((rs1 & 0x1F) << 15) | (0x1 << 12) | 0x73
    return inst(f"csrw 0x{csr:x}, x{rs1}", word, role)


def mret(role: str = "exception_return") -> EncodedInstruction:
    return inst("mret", 0x30200073, role)


def ecall(role: str = "exception") -> EncodedInstruction:
    return inst("ecall", 0x00000073, role)


def ebreak(role: str = "end") -> EncodedInstruction:
    return inst("ebreak", 0x00100073, role)


def xstrap_good(role: str = "end") -> EncodedInstruction:
    return inst(".word 0x0005006b # xiangshan good trap", 0x0005006B, role)


def amoadd_d(rd: int, rs1: int, rs2: int, aq: bool = True, rl: bool = True, role: str = "amo") -> EncodedInstruction:
    return inst(f"amoadd.d{' .aqrl' if aq and rl else ''} x{rd}, x{rs2}, (x{rs1})", amo_type(rd, rs1, rs2, 0x00, aq, rl), role)


def amoswap_d(rd: int, rs1: int, rs2: int, aq: bool = True, rl: bool = True, role: str = "amo") -> EncodedInstruction:
    return inst(f"amoswap.d{' .aqrl' if aq and rl else ''} x{rd}, x{rs2}, (x{rs1})", amo_type(rd, rs1, rs2, 0x01, aq, rl), role)


def lr_d(rd: int, rs1: int, aq: bool = True, rl: bool = False, role: str = "lr") -> EncodedInstruction:
    return inst(f"lr.d{' .aq' if aq else ''} x{rd}, (x{rs1})", amo_type(rd, rs1, 0, 0x02, aq, rl), role)


def sc_d(rd: int, rs1: int, rs2: int, aq: bool = False, rl: bool = True, role: str = "sc") -> EncodedInstruction:
    return inst(f"sc.d{' .rl' if rl else ''} x{rd}, x{rs2}, (x{rs1})", amo_type(rd, rs1, rs2, 0x03, aq, rl), role)


def li_small(rd: int, value: int, role: str = "setup") -> list[EncodedInstruction]:
    if -2048 <= value <= 2047:
        return [addi(rd, 0, value, role)]
    high = (value + 0x800) >> 12
    low = value - (high << 12)
    return [lui(rd, high & 0xFFFFF, role), addi(rd, rd, low, role)]


def li_pmem_addr(rd: int, addr: int, role: str = "addr") -> list[EncodedInstruction]:
    if addr < PMEM_BASE:
        raise ValueError(f"SFuzz scenario address 0x{addr:x} is below PMEM_BASE")
    offset = addr - PMEM_BASE
    seq = [lui(rd, 0x10000, role), slli(rd, rd, 3, role)]
    if -2048 <= offset <= 2047:
        if offset:
            seq.append(addi(rd, rd, offset, role))
        return seq
    scratch = 30 if rd != 30 else 29
    seq.extend(li_small(scratch, offset, role))
    seq.append(add(rd, rd, scratch, role))
    return seq


def _shared_region(name: str, base: int, size: int) -> SharedRegion:
    init = bytearray(size)
    for index in range(0, size, 8):
        init[index : index + 8] = (0x1000 + index).to_bytes(8, "little", signed=False)
    return SharedRegion(name=name, base=base, size=size, init=bytes(init))


def _finish(seq: list[EncodedInstruction]) -> None:
    seq.extend([addi(31, 31, 1, "depth"), addi(10, 0, 0, "good_trap_code"), xstrap_good()])


def _append_runtime_stress_loop(seq: list[EncodedInstruction], iterations: int) -> None:
    if iterations <= 0:
        return
    seq.extend(li_small(28, max(1, iterations), "stress_loop_count"))
    seq.extend(
        [
            ld(29, 5, 0, "stress_loop_load"),
            addi(29, 29, 1, "stress_loop_dependency"),
            sd(29, 5, 0, "stress_loop_store"),
            fence_rw_rw("stress_loop_fence"),
            addi(28, 28, -1, "stress_loop_count"),
            bne(28, 0, -20, "stress_loop_branch"),
        ]
    )


def _append_exception_handler(seq: list[EncodedInstruction]) -> None:
    while len(seq) * 4 < EXCEPTION_HANDLER_OFFSET:
        seq.append(nop())
    if len(seq) * 4 != EXCEPTION_HANDLER_OFFSET:
        raise ValueError("exception handler offset overlaps the generated scenario body")
    seq.extend(
        [
            csrr(29, 0x341, "exception_handler"),  # mepc
            addi(29, 29, 4, "exception_handler"),
            csrw(0x341, 29, "exception_handler"),
            mret(),
        ]
    )


def _block(core: int, label: str, seq: Iterable[EncodedInstruction]) -> InstructionBlock:
    return InstructionBlock(core=core, label=label, instructions=tuple(seq))


def _scenario(
    *,
    family: str,
    operator: str,
    target_groups: tuple[str, ...],
    core0: list[EncodedInstruction],
    shared: tuple[SharedRegion, ...],
    expected: tuple[str, ...],
    variant: int,
    core1: list[EncodedInstruction] | None = None,
    sync: tuple[str, ...] = (),
    requires_core1_handoff: bool = False,
    core1_handoff_enabled: bool = False,
    runtime_profile: str = "short",
    stress_iterations: int = 0,
    target_min_wall_time_sec: int = 0,
) -> ScenarioIR:
    blocks = [_block(0, f"{family}_core0", core0)]
    cores = [0]
    if core1:
        blocks.append(_block(1, f"{family}_core1", core1))
        cores.append(1)
    scenario_id = f"{family}-{operator}-{variant:04d}"
    return ScenarioIR(
        scenario_id=scenario_id,
        scenario_family=family,
        target_groups=target_groups,
        cores=tuple(cores),
        shared_regions=shared,
        instruction_blocks=tuple(blocks),
        synchronization_points=sync,
        expected_micro_events=expected,
        semantic_operator=operator,
        requires_core1_handoff=requires_core1_handoff,
        core1_handoff_enabled=core1_handoff_enabled,
        runtime_profile=runtime_profile,
        stress_iterations=stress_iterations,
        target_min_wall_time_sec=target_min_wall_time_sec,
    )


def _base_for_variant(variant: int) -> int:
    return DEFAULT_SHARED_BASE + (variant % 16) * 0x1000


def _variant_depth(variant: int, *, base: int = 2, span: int = 6) -> int:
    return base + (variant % max(1, span))


def _variant_stride(variant: int) -> int:
    return (1, 2, 4, 8)[variant % 4] * 8


def _memory_pressure_lines(variant: int) -> int:
    return 8 + (variant % 5) * 4


def generate_scenario(
    family: str,
    *,
    operator: str | None = None,
    variant: int = 0,
    rng: random.Random | None = None,
    core1_handoff_enabled: bool = False,
    runtime_profile: str = "short",
    stress_iterations: int = 0,
    target_min_wall_time_sec: int = 0,
) -> ScenarioIR:
    if family not in SCENARIO_FAMILIES:
        raise ValueError(f"unsupported SFuzz scenario family: {family}")
    rnd = rng or random.Random(variant)
    op = operator or family_default_operator(family)
    if runtime_profile not in {"short", "long"}:
        raise ValueError(f"unsupported SFuzz runtime profile: {runtime_profile}")
    if runtime_profile == "long" and stress_iterations <= 0:
        stress_iterations = max(4096, target_min_wall_time_sec * 4096)
    base = _base_for_variant(variant + rnd.randrange(16))
    alias_offset = 8 if op != "create_cross_cacheline_alias" else DEFAULT_CACHELINE_BYTES
    shared_size = 0x6000 if family == "tlb_refill_memory" else 512
    depth = _variant_depth(variant)
    stride = _variant_stride(variant)
    shared = (_shared_region("shared0", base, shared_size),)

    core0: list[EncodedInstruction] = []
    core0.extend(li_pmem_addr(5, base))
    core0.extend(li_small(6, 1 + (variant & 7)))
    core0.extend(li_small(7, 2 + (variant & 7)))

    core1: list[EncodedInstruction] = []
    requires_core1 = False
    sync: tuple[str, ...] = ()
    needs_exception_handler = False

    if family == "memory_alias":
        for index in range(depth):
            offset = (index * stride) % 96
            core0.extend([sd(6 + index % 2, 5, offset), ld(8 + index % 8, 5, offset)])
        core0.extend([sd(8, 5, alias_offset), ld(9, 5, alias_offset)])
        target_groups = ("sfuzz_lsq", "sfuzz_dcache")
        expected = ("load_store_forward", "load_miss", "store_miss")
    elif family == "cacheline_conflict":
        offsets = tuple(((index * stride) % DEFAULT_CACHELINE_BYTES) for index in range(max(4, depth + 2)))
        if op == "create_cross_cacheline_alias":
            offsets = tuple(offset + (index % 2) * DEFAULT_CACHELINE_BYTES for index, offset in enumerate(offsets))
        for idx, offset in enumerate(offsets):
            core0.extend([sd(6 + idx % 2, 5, offset), ld(10 + idx, 5, offset)])
        target_groups = ("sfuzz_dcache", "sfuzz_lsq")
        expected = ("dcache_bank_conflict", "load_store_forward")
        if op == "insert_multicore_pingpong":
            requires_core1 = True
            sync = ("same_cacheline_pingpong",)
            core1.extend(li_pmem_addr(5, base))
            core1.extend(li_small(6, 9))
            core1.extend([ld(8, 5, 0), sd(6, 5, DEFAULT_CACHELINE_BYTES - 8), fence_rw_rw()])
            _finish(core1)
            target_groups = ("sfuzz_coherence", "sfuzz_dcache", "sfuzz_lsq")
            expected = ("cross_core_probe", "probe_ack", "release_fire", "dcache_bank_conflict")
    elif family == "load_store_dependency":
        core0.extend([sd(6, 5, 0), ld(8, 5, 0), add(9, 8, 6), sd(9, 5, 8), ld(10, 5, 8)])
        if op in {"increase_replay_pressure", "create_load_use_dependency"}:
            for index in range(depth):
                load_rd = 11 + (index % 6)
                add_rd = 17 + (index % 6)
                offset = 16 + index * 8
                core0.extend([ld(load_rd, 5, offset), add(add_rd, load_rd, 9), sd(add_rd, 5, offset + 8)])
        target_groups = ("sfuzz_lsq", "sfuzz_resource")
        expected = ("load_store_forward", "load_replay", "store_replay")
    elif family == "store_load_reordering":
        for index in range(depth):
            offset = index * 8
            core0.extend([sd(6 + index % 2, 5, offset), ld(8 + index % 8, 5, offset ^ 8)])
        core0.extend([sd(7, 5, 8), ld(9, 5, 0), fence_rw_rw(), ld(10, 5, 8)])
        target_groups = ("sfuzz_lsq", "sfuzz_fence")
        expected = ("load_store_violation", "fence_fire", "fence_drain")
    elif family == "amo_contention":
        core0.append(sd(6, 5, 0))
        for index in range(depth):
            if index % 2:
                core0.append(amoswap_d(9 + index % 4, 5, 6))
            else:
                core0.append(amoadd_d(8 + index % 4, 5, 7))
        core0.append(ld(10, 5, 0))
        requires_core1 = True
        sync = ("same_word_amo_contention",)
        core1.extend(li_pmem_addr(5, base))
        core1.extend(li_small(6, 3))
        core1.extend([amoadd_d(8, 5, 6), sd(6, 5, 0), fence_rw_rw()])
        _finish(core1)
        target_groups = ("sfuzz_atomic", "sfuzz_fence", "sfuzz_lsq")
        expected = ("amo_fire", "amo_conflict", "fence_fire")
    elif family == "lrsc_success_fail":
        for index in range(depth):
            core0.extend([lr_d(8, 5), addi(8, 8, 1 + (index & 1)), sc_d(9, 5, 8), ld(10, 5, 0)])
        if op == "force_sc_fail_window":
            requires_core1 = True
            sync = ("same_word_sc_fail_window",)
            core1.extend(li_pmem_addr(5, base))
            core1.extend(li_small(6, 7))
            core1.extend([sd(6, 5, 0), fence_rw_rw()])
            _finish(core1)
        target_groups = ("sfuzz_atomic", "sfuzz_lsq")
        expected = ("lr_seen", "sc_success", "sc_fail" if requires_core1 else "local_sc_result")
    elif family == "fence_ordering":
        for index in range(depth):
            offset = (index % 4) * 8
            core0.extend([sd(6 + index % 2, 5, offset), fence_rw_rw(), ld(8 + index % 8, 5, offset)])
        core0.extend([sd(7, 5, 8), fence_rw_rw(), ld(9, 5, 8)])
        if op == "insert_fence_before_after_amo":
            for index in range(max(1, depth // 2)):
                core0.extend([fence_rw_rw(), amoadd_d(10 + index % 4, 5, 6), fence_rw_rw()])
        requires_core1 = op == "insert_fence_before_after_amo"
        if requires_core1:
            sync = ("competing_fence_amo_window",)
            core1.extend(li_pmem_addr(5, base))
            core1.extend(li_small(6, 11))
            core1.extend([sd(6, 5, 0), fence_rw_rw(), ld(8, 5, 0)])
            _finish(core1)
        target_groups = ("sfuzz_fence", "sfuzz_lsq", "sfuzz_atomic")
        expected = ("fence_fire", "fence_wait", "fence_drain", "amo_fire" if op == "insert_fence_before_after_amo" else "load_store_forward")
    elif family == "branch_flush_memory":
        for index in range(depth):
            core0.extend([sd(6 + index % 2, 5, (index % 4) * 8), bne(6, 7, 8), ld(8 + index % 8, 5, 0)])
        core0.extend([sd(7, 5, 8), ld(9, 5, 8)])
        target_groups = ("sfuzz_branch", "sfuzz_lsq", "sfuzz_frontend")
        expected = ("branch_redirect", "redirect_from_branch", "ibuffer_flush", "load_replay")
    elif family == "exception_during_memory":
        handler_addr = PMEM_BASE + EXCEPTION_HANDLER_OFFSET
        core0.extend(li_pmem_addr(28, handler_addr, "exception_handler_addr"))
        core0.append(csrw(0x305, 28, "exception_setup"))  # mtvec
        core0.extend([sd(6, 5, 0), ld(8, 5, 0), ecall(), ld(9, 5, 8)])
        needs_exception_handler = True
        target_groups = ("sfuzz_exception", "sfuzz_lsq", "sfuzz_rob")
        expected = ("trap_enter", "redirect_from_exception", "rob_commit_valid")
    elif family == "tlb_refill_memory":
        core0.extend([sfence_vma(), ld(8, 5, 0)])
        for page in range(1, 5 + (variant % 4)):
            core0.extend(li_pmem_addr(5, base + page * 0x1000))
            core0.append(ld(8 + page, 5, 0))
        target_groups = ("sfuzz_mmu", "sfuzz_lsq", "sfuzz_dcache")
        expected = ("dtlb_miss", "ptw_req_fire", "ptw_resp_fire")
    elif family == "mshr_pressure":
        for line in range(_memory_pressure_lines(variant)):
            core0.extend(li_pmem_addr(5, base + line * DEFAULT_CACHELINE_BYTES))
            core0.append(ld(8 + (line % 8), 5, 0))
        target_groups = ("sfuzz_dcache", "sfuzz_resource", "sfuzz_lsq")
        expected = ("mshr_alloc", "mshr_retry", "mshr_full", "load_miss")
    elif family == "queue_backpressure":
        for offset in range(0, 64 + depth * 16, 8):
            core0.extend([sd(6, 5, offset), ld(8, 5, offset)])
        core0.extend([fence_rw_rw(), addi(6, 6, 1, "bounded_loop"), bne(6, 7, -4)])
        target_groups = ("sfuzz_resource", "sfuzz_rob", "sfuzz_lsq")
        expected = ("fence_wait", "store_replay", "load_replay", "rob_commit_valid")
    else:
        raise AssertionError(f"unhandled family {family}")

    applied_stress_iterations = stress_iterations if runtime_profile == "long" and not needs_exception_handler else 0
    _append_runtime_stress_loop(core0, applied_stress_iterations)
    _finish(core0)
    if needs_exception_handler:
        _append_exception_handler(core0)
    return _scenario(
        family=family,
        operator=op,
        target_groups=target_groups,
        core0=core0,
        core1=core1 or None,
        shared=shared,
        expected=expected,
        variant=variant,
        sync=sync,
        requires_core1_handoff=requires_core1,
        core1_handoff_enabled=core1_handoff_enabled,
        runtime_profile=runtime_profile if applied_stress_iterations else "short",
        stress_iterations=applied_stress_iterations,
        target_min_wall_time_sec=target_min_wall_time_sec if applied_stress_iterations else 0,
    )


def family_default_operator(family: str) -> str:
    try:
        return FAMILY_DEFAULT_OPERATOR[family]
    except KeyError as exc:
        raise ValueError(f"no default semantic operator for {family}") from exc


def choose_semantic_operator(
    focus_group: str,
    seed_ir_targets: str = "",
    *,
    rng: random.Random | None = None,
    core1_handoff_enabled: bool = False,
    stalled_operators: Iterable[str] = (),
) -> str:
    rnd = rng or random.Random()
    candidates = list(GROUP_OPERATOR_HINTS.get(focus_group, ()))
    if not candidates and seed_ir_targets:
        weighted: list[str] = []
        for item in seed_ir_targets.split(";"):
            if ":" not in item:
                continue
            group, weight_text = item.split(":", 1)
            try:
                weight = max(1, int(weight_text))
            except ValueError:
                continue
            for operator in GROUP_OPERATOR_HINTS.get(group, ()):
                weighted.extend([operator] * min(8, weight))
        candidates = weighted
    if not candidates:
        candidates = list(SEMANTIC_OPERATORS)
    if not core1_handoff_enabled:
        candidates = [
            op
            for op in candidates
            if op
            not in {
                "force_sc_fail_window",
                "insert_multicore_pingpong",
            }
        ] or ["insert_load_store_pair"]
    stalled = set(stalled_operators)
    if stalled and len(set(candidates)) > 1:
        filtered = [op for op in candidates if op not in stalled]
        if filtered:
            candidates = filtered
    return candidates[rnd.randrange(len(candidates))]


def scenario_from_operator(
    operator: str,
    *,
    variant: int = 0,
    rng: random.Random | None = None,
    core1_handoff_enabled: bool = False,
    runtime_profile: str = "short",
    stress_iterations: int = 0,
    target_min_wall_time_sec: int = 0,
) -> ScenarioIR:
    if operator not in SEMANTIC_OPERATORS:
        raise ValueError(f"unsupported SFuzz semantic operator: {operator}")
    return generate_scenario(
        OPERATOR_FAMILY[operator],
        operator=operator,
        variant=variant,
        rng=rng,
        core1_handoff_enabled=core1_handoff_enabled,
        runtime_profile=runtime_profile,
        stress_iterations=stress_iterations,
        target_min_wall_time_sec=target_min_wall_time_sec,
    )


def seed_from_scenario(scenario: ScenarioIR) -> SfuzSeed:
    shared = [(region.base, region.init) for region in scenario.shared_regions]
    tags = [
        "sfuzz-scenario",
        f"scenario:{scenario.scenario_family}",
        f"operator:{scenario.semantic_operator}",
        *[f"target:{group}" for group in scenario.target_groups],
        *[f"event:{event}" for event in scenario.expected_micro_events],
        f"requires_core1_handoff:{str(scenario.requires_core1_handoff).lower()}",
        f"core1_handoff_enabled:{str(scenario.core1_handoff_enabled).lower()}",
        f"runtime_profile:{scenario.runtime_profile}",
        f"stress_iterations:{scenario.stress_iterations}",
        f"target_min_wall_time_sec:{scenario.target_min_wall_time_sec}",
    ]
    if scenario.requires_core1_handoff and not scenario.core1_handoff_enabled:
        tags.append("single-core-fallback")
    return SfuzSeed(
        core0_prog=scenario.core_payload(0),
        core1_prog=scenario.core_payload(1),
        shared_mem_init=shared,
        interrupt_plan_raw=[],
        name=scenario.scenario_id,
        description=(
            f"SFuzz semantic scenario family={scenario.scenario_family}; "
            f"operator={scenario.semantic_operator}; "
            f"expected={','.join(scenario.expected_micro_events)}"
        ),
        tags=tags,
    )


def write_scenario_artifacts(
    output: Path,
    scenario: ScenarioIR,
    *,
    write_sidecars: bool = True,
) -> tuple[Path, Path | None, Path | None]:
    write_sfuz_seed(output, seed_from_scenario(scenario))
    asm_path: Path | None = None
    meta_path: Path | None = None
    if write_sidecars:
        asm_path = output.with_suffix(".S")
        meta_path = output.with_suffix(".scenario.json")
        asm_path.write_text(scenario.assembly(), encoding="utf-8")
        meta_path.write_text(json.dumps(scenario.metadata(), indent=2, sort_keys=True), encoding="utf-8")
    return output, asm_path, meta_path


def generate_scenario_corpus(
    output_dir: Path,
    *,
    count: int = len(SCENARIO_FAMILIES),
    rng_seed: int = 1,
    core1_handoff_enabled: bool = False,
    runtime_profile: str = "short",
    target_min_wall_time_sec: int = 0,
) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    rnd = random.Random(rng_seed)
    paths: list[Path] = []
    for index in range(max(0, count)):
        family = SCENARIO_FAMILIES[index % len(SCENARIO_FAMILIES)]
        scenario = generate_scenario(
            family,
            variant=index,
            rng=rnd,
            core1_handoff_enabled=core1_handoff_enabled,
            runtime_profile=runtime_profile,
            target_min_wall_time_sec=target_min_wall_time_sec,
        )
        output = output_dir / f"{index:04d}-{slugify(scenario.scenario_id)}.sfuz"
        write_scenario_artifacts(output, scenario)
        paths.append(output)
    return paths


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate SFuzz semantic scenario .sfuz seeds")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--count", type=int, default=len(SCENARIO_FAMILIES))
    parser.add_argument("--rng-seed", type=int, default=1)
    parser.add_argument("--enable-core1-handoff", action="store_true")
    parser.add_argument("--runtime-profile", choices=["short", "long"], default="short")
    parser.add_argument("--target-min-wall-time-sec", type=int, default=0)
    args = parser.parse_args(argv)
    paths = generate_scenario_corpus(
        args.output_dir,
        count=args.count,
        rng_seed=args.rng_seed,
        core1_handoff_enabled=args.enable_core1_handoff,
        runtime_profile=args.runtime_profile,
        target_min_wall_time_sec=args.target_min_wall_time_sec,
    )
    for path in paths:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
