from __future__ import annotations

import copy
import random
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


DEFAULT_RISCV_GCC = "/nfs/share/opt/riscv/bin/riscv64-unknown-elf-gcc"
DEFAULT_RISCV_OBJCOPY = "/nfs/share/opt/riscv/bin/riscv64-unknown-elf-objcopy"


@dataclass(frozen=True)
class ProgramConfig:
    initial_seed_block_count: int = 4
    initial_seed_instructions_per_block: int = 5
    enable_rv64a: bool = False
    enable_rv64im: bool = False
    enable_insert_memory_access_sequence: bool = True
    max_operation_count: int = 3
    link_address: int = 0x80000000
    memory_bytes: int = 4096
    stack_bytes: int = 4096


@dataclass
class Instruction:
    inst_type: str
    opcode: str
    operands: list[str]

    @classmethod
    def random(cls, rnd: random.Random, config: ProgramConfig) -> "Instruction":
        inst_type = rnd.choice(instruction_types(config))
        return cls(inst_type, random_opcode(inst_type, rnd, config), random_operands(inst_type, rnd, config))

    def clone(self) -> "Instruction":
        return Instruction(self.inst_type, self.opcode, list(self.operands))

    def generate(self) -> str:
        if self.inst_type == "Memory":
            return f"{self.opcode} {self.operands[0]}, {self.operands[2]}({self.operands[1]})"
        if self.inst_type == "AtomicArg2":
            return f"{self.opcode} {self.operands[0]}, ({self.operands[1]})"
        if self.inst_type == "AtomicArg3":
            return f"{self.opcode} {self.operands[0]}, {self.operands[1]}, ({self.operands[2]})"
        if not self.operands:
            return self.opcode
        return f"{self.opcode} " + ", ".join(self.operands)


@dataclass
class Block:
    label: str
    instructions: list[Instruction]

    @classmethod
    def random(cls, label: str, instruction_count: int, rnd: random.Random, config: ProgramConfig) -> "Block":
        return cls(label, [Instruction.random(rnd, config) for _ in range(instruction_count)])

    def clone(self) -> "Block":
        return Block(self.label, [instruction.clone() for instruction in self.instructions])

    def generate(self) -> str:
        lines = [f"{self.label}:"]
        lines.extend(f"    {instruction.generate()}" for instruction in self.instructions)
        return "\n".join(lines) + "\n"

    def mutate(self, rnd: random.Random, config: ProgramConfig) -> list[str]:
        op_count = 8 if config.enable_insert_memory_access_sequence else 7
        operation_names = [
            "swap_inst",
            "mutate_opcode",
            "mutate_operands",
            "mutate_operand",
            "mutate_inst",
            "insert_inst",
            "remove_inst",
            "insert_memory_access_sequence",
        ][:op_count]
        applied: list[str] = []
        if rnd.randrange(2) == 0:
            for _ in range(1 + rnd.randrange(max(1, config.max_operation_count))):
                applied.append(self.apply_mutation(rnd.choice(operation_names), rnd, config))
        else:
            operation = rnd.choice(operation_names)
            for _ in range(1 + rnd.randrange(max(1, config.max_operation_count))):
                applied.append(self.apply_mutation(operation, rnd, config))
        return applied

    def apply_mutation(self, operation: str, rnd: random.Random, config: ProgramConfig) -> str:
        if not self.instructions:
            self.instructions.append(Instruction.random(rnd, config))
            return "insert_inst"

        if operation == "swap_inst":
            i = rnd.randrange(len(self.instructions))
            j = rnd.randrange(len(self.instructions))
            self.instructions[i], self.instructions[j] = self.instructions[j], self.instructions[i]
        elif operation == "mutate_opcode":
            inst = self.instructions[rnd.randrange(len(self.instructions))]
            inst.opcode = random_opcode(inst.inst_type, rnd, config)
        elif operation == "mutate_operands":
            inst = self.instructions[rnd.randrange(len(self.instructions))]
            inst.operands = random_operands(inst.inst_type, rnd, config)
        elif operation == "mutate_operand":
            inst = self.instructions[rnd.randrange(len(self.instructions))]
            if inst.operands:
                operand_index = rnd.randrange(len(inst.operands))
                inst.operands[operand_index] = random_operand(inst.inst_type, operand_index, rnd, config)
        elif operation == "mutate_inst":
            self.instructions[rnd.randrange(len(self.instructions))] = Instruction.random(rnd, config)
        elif operation == "insert_inst":
            index = rnd.randrange(len(self.instructions))
            self.instructions.insert(index, Instruction.random(rnd, config))
        elif operation == "remove_inst":
            if len(self.instructions) > 1:
                del self.instructions[rnd.randrange(len(self.instructions))]
        elif operation == "insert_memory_access_sequence":
            load_address = Instruction(
                "PseudoLoadAddress",
                random_opcode("PseudoLoadAddress", rnd, config),
                random_operands("PseudoLoadAddress", rnd, config),
            )
            memory_access = Instruction(
                "Memory",
                random_opcode("Memory", rnd, config),
                [random_operand("Memory", 0, rnd, config), load_address.operands[0], "0"],
            )
            index = rnd.randrange(len(self.instructions))
            self.instructions.insert(index, load_address)
            self.instructions.insert(index + 1, memory_access)
        else:
            raise ValueError(f"unsupported SurgeFuzz mutation operator: {operation}")
        return operation


@dataclass
class Program:
    blocks: list[Block]

    @classmethod
    def random(cls, rnd: random.Random, config: ProgramConfig) -> "Program":
        return cls(
            [
                Block.random(f"label_{index}", config.initial_seed_instructions_per_block, rnd, config)
                for index in range(config.initial_seed_block_count)
            ]
        )

    def clone(self) -> "Program":
        return copy.deepcopy(self)

    def mutate(self, rnd: random.Random, config: ProgramConfig) -> list[str]:
        if not self.blocks:
            self.blocks.append(Block.random("label_0", config.initial_seed_instructions_per_block, rnd, config))
        applied: list[str] = []
        for _ in range(1 + rnd.randrange(2)):
            block = self.blocks[rnd.randrange(len(self.blocks))]
            applied.extend(block.mutate(rnd, config))
        return applied

    def generate_body(self) -> str:
        return "\n".join(block.generate() for block in self.blocks)

    def generate_assembly(self, config: ProgramConfig, header: str | None = None, footer: str | None = None) -> str:
        if header is None:
            header = default_header(config)
        if footer is None:
            footer = default_footer(config)
        return header + self.generate_body() + footer

    def write_assembly(self, path: Path, config: ProgramConfig, header: str | None = None, footer: str | None = None) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.generate_assembly(config, header, footer), encoding="utf-8")


def instruction_types(config: ProgramConfig) -> list[str]:
    base = [
        "IntRegImm",
        "IntRegImmShift",
        "IntRegReg",
        "Branch",
        "Memory",
        "PseudoArg0",
        "PseudoLi",
        "PseudoLoadAddress",
    ]
    if config.enable_rv64im:
        base.insert(2, "IntRegImmShiftW")
    if config.enable_rv64a:
        base.extend(["AtomicArg2", "AtomicArg3"])
    return base


def random_opcode(inst_type: str, rnd: random.Random, config: ProgramConfig) -> str:
    opcode_lists = {
        "IntRegImm": ["addi", "slti", "sltiu", "xori", "ori", "andi"],
        "IntRegImmShift": ["slli", "srli", "srai"],
        "IntRegImmShiftW": ["slliw", "srliw", "sraiw"],
        "IntRegReg": [
            "add",
            "sub",
            "sll",
            "slt",
            "sltu",
            "xor",
            "srl",
            "sra",
            "or",
            "and",
            "mul",
            "mulh",
            "mulhsu",
            "mulhu",
            "div",
            "divu",
            "rem",
            "remu",
        ],
        "Branch": ["beq", "bne", "blt", "bge", "bltu", "bgeu"],
        "Memory": ["lb", "lh", "lw", "lbu", "lhu", "sb", "sh", "sw"],
        "PseudoArg0": ["nop", "fence"],
        "PseudoLi": ["li"],
        "PseudoLoadAddress": ["la"],
        "AtomicArg2": ["lr.w", "lr.d"],
        "AtomicArg3": [
            "sc.w",
            "amoswap.w",
            "amoadd.w",
            "amoxor.w",
            "amoand.w",
            "amoor.w",
            "amomin.w",
            "amomax.w",
            "amominu.w",
            "amomaxu.w",
            "sc.d",
            "amoswap.d",
            "amoadd.d",
            "amoxor.d",
            "amoand.d",
            "amoor.d",
            "amomin.d",
            "amomax.d",
            "amominu.d",
            "amomaxu.d",
        ],
    }
    if config.enable_rv64im:
        opcode_lists["IntRegImm"] = [*opcode_lists["IntRegImm"], "addiw"]
        opcode_lists["IntRegReg"] = [
            "add",
            "sub",
            "sll",
            "slt",
            "sltu",
            "xor",
            "srl",
            "sra",
            "or",
            "and",
            "mul",
            "mulh",
            "mulhsu",
            "mulhu",
            "div",
            "divu",
            "rem",
            "remu",
            "addw",
            "subw",
            "sllw",
            "srlw",
            "sraw",
            "mulw",
            "divw",
            "divuw",
            "remw",
            "remuw",
        ]
        opcode_lists["Memory"] = [*opcode_lists["Memory"], "lwu", "ld", "sd"]
    return rnd.choice(opcode_lists[inst_type])


def random_operands(inst_type: str, rnd: random.Random, config: ProgramConfig) -> list[str]:
    counts = {
        "IntRegImm": 3,
        "IntRegImmShift": 3,
        "IntRegImmShiftW": 3,
        "IntRegReg": 3,
        "Branch": 3,
        "Memory": 3,
        "PseudoArg0": 0,
        "PseudoLi": 2,
        "PseudoLoadAddress": 2,
        "AtomicArg2": 2,
        "AtomicArg3": 3,
    }
    return [random_operand(inst_type, index, rnd, config) for index in range(counts[inst_type])]


def random_operand(inst_type: str, index: int, rnd: random.Random, config: ProgramConfig) -> str:
    if inst_type == "IntRegImm":
        return random_register(rnd) if index < 2 else str(rnd.randrange(-(2**11), 2**11))
    if inst_type == "IntRegImmShift":
        return random_register(rnd) if index < 2 else str(rnd.randrange(64 if config.enable_rv64im else 32))
    if inst_type == "IntRegImmShiftW":
        return random_register(rnd) if index < 2 else str(rnd.randrange(32))
    if inst_type in {"IntRegReg", "AtomicArg3"}:
        return random_register(rnd)
    if inst_type == "Branch":
        return random_register(rnd) if index < 2 else random_label(rnd, config)
    if inst_type == "Memory":
        return random_register(rnd) if index < 2 else str(rnd.randrange(2**11))
    if inst_type == "PseudoLi":
        return random_register(rnd) if index == 0 else str(rnd.randrange(0, 32))
    if inst_type == "PseudoLoadAddress":
        return random_register(rnd) if index == 0 else f"test_memory + {rnd.randrange(2**11)}"
    if inst_type == "AtomicArg2":
        return random_register(rnd)
    raise ValueError(f"unsupported operand type: {inst_type}")


def random_register(rnd: random.Random) -> str:
    while True:
        reg = rnd.randrange(32)
        if reg not in {0, 1, 2}:
            return f"x{reg}"


def random_label(rnd: random.Random, config: ProgramConfig) -> str:
    return f"label_{rnd.randrange(max(1, config.initial_seed_block_count))}"


def default_header(config: ProgramConfig) -> str:
    return (
        "    .option norvc\n"
        "    .section .text\n"
        f"    .org 0x0\n"
        "    .globl _start\n"
        "_start:\n"
        "    la sp, stack_top\n"
        "    li x3, 0\n"
        "    li x4, 0\n"
        "    li x5, 0\n"
        "    j label_0\n"
        "\n"
    )


def default_footer(config: ProgramConfig) -> str:
    return (
        "surgefuzz_done:\n"
        "    j surgefuzz_done\n"
        "\n"
        "    .section .data\n"
        "    .balign 8\n"
        "test_memory:\n"
        f"    .zero {config.memory_bytes}\n"
        "\n"
        "    .section .bss\n"
        "    .balign 16\n"
        "stack:\n"
        f"    .zero {config.stack_bytes}\n"
        "stack_top:\n"
    )


def resolve_tool(explicit: str | None, fallback: str) -> str:
    if explicit:
        path = Path(explicit).expanduser()
        return str(path)
    found = shutil.which(Path(fallback).name)
    return found or fallback


def compile_program(
    program: Program,
    *,
    output_bin: Path,
    output_asm: Path,
    output_elf: Path,
    config: ProgramConfig,
    gcc: str | None = None,
    objcopy: str | None = None,
    header: str | None = None,
    footer: str | None = None,
) -> tuple[Path, Path, Path]:
    output_bin.parent.mkdir(parents=True, exist_ok=True)
    output_asm.parent.mkdir(parents=True, exist_ok=True)
    output_elf.parent.mkdir(parents=True, exist_ok=True)
    program.write_assembly(output_asm, config, header, footer)

    gcc_bin = resolve_tool(gcc, DEFAULT_RISCV_GCC)
    objcopy_bin = resolve_tool(objcopy, DEFAULT_RISCV_OBJCOPY)
    compile_cmd = [
        gcc_bin,
        "-nostdlib",
        "-nostartfiles",
        "-march=rv64imac",
        "-mabi=lp64",
        f"-Wl,-Ttext={config.link_address:#x}",
        "-Wl,--no-relax",
        "-o",
        str(output_elf),
        str(output_asm),
    ]
    subprocess.run(compile_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    subprocess.run(
        [objcopy_bin, "-O", "binary", str(output_elf), str(output_bin)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return output_asm, output_elf, output_bin
