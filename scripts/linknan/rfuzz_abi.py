from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import VcsContext


CONTROL_INPUT_NAMES = {
    "clock",
    "reset",
    "difftest_perfCtrl_clean",
    "difftest_perfCtrl_dump",
    "difftest_logCtrl_begin",
    "difftest_logCtrl_end",
    "difftest_logCtrl_level",
    "difftest_uart_in_ch",
}

CONTROL_OUTPUT_NAMES = {
    "difftest_exit",
    "difftest_step",
    "difftest_uart_out_valid",
    "difftest_uart_out_ch",
    "difftest_uart_in_valid",
}


@dataclass(frozen=True)
class RfuzzAbiAudit:
    runner_abi: str
    raw_pin_stream_supported: bool
    raw_pin_stream_reason: str
    top_module: str
    top_input_pins: int
    fuzzable_input_pins: int
    fuzzable_input_names: list[str]
    ignored_control_inputs: list[str]
    pin_stream_driver_supported: bool
    workload_plusarg_supported: bool
    workload_plusarg_required: bool
    validity_supported: bool
    validity_source: str
    deterministic_reset_supported: bool
    deterministic_reset_model: str
    sparse_memory_supported: bool
    sparse_memory_model: str
    notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "runner_abi": self.runner_abi,
            "raw_pin_stream_supported": self.raw_pin_stream_supported,
            "raw_pin_stream_reason": self.raw_pin_stream_reason,
            "top_module": self.top_module,
            "top_input_pins": self.top_input_pins,
            "fuzzable_input_pins": self.fuzzable_input_pins,
            "fuzzable_input_names": self.fuzzable_input_names,
            "ignored_control_inputs": self.ignored_control_inputs,
            "pin_stream_driver_supported": self.pin_stream_driver_supported,
            "workload_plusarg_supported": self.workload_plusarg_supported,
            "workload_plusarg_required": self.workload_plusarg_required,
            "validity_supported": self.validity_supported,
            "validity_source": self.validity_source,
            "deterministic_reset_supported": self.deterministic_reset_supported,
            "deterministic_reset_model": self.deterministic_reset_model,
            "sparse_memory_supported": self.sparse_memory_supported,
            "sparse_memory_model": self.sparse_memory_model,
            "notes": self.notes,
        }


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def parse_simtop_ports(simtop_sv: Path) -> list[dict[str, Any]]:
    text = read_text(simtop_sv)
    match = re.search(r"module\s+SimTop\s*\((.*?)\);\s*", text, re.S)
    if not match:
        return []
    ports: list[dict[str, Any]] = []
    for raw_line in match.group(1).splitlines():
        line = raw_line.strip().rstrip(",;")
        port = re.match(r"(input|output)\s+(?:\[(\d+)\s*:\s*(\d+)\]\s+)?([A-Za-z_][A-Za-z0-9_$]*)", line)
        if not port:
            continue
        msb = port.group(2)
        lsb = port.group(3)
        width = 1
        if msb is not None and lsb is not None:
            width = abs(int(msb) - int(lsb)) + 1
        ports.append(
            {
                "direction": port.group(1),
                "name": port.group(4),
                "width": width,
                "declaration": line,
            }
        )
    return ports


def audit_linknan_rfuzz_abi(ctx: VcsContext) -> RfuzzAbiAudit:
    simtop_sv = ctx.build_dir / "rtl" / "SimTop.sv"
    tb_top_v = ctx.linknan_root / "dependencies" / "difftest" / "src" / "test" / "vsrc" / "vcs" / "top.v"
    endpoint_sv = (
        ctx.linknan_root
        / "dependencies"
        / "difftest"
        / "src"
        / "test"
        / "vsrc"
        / "vcs"
        / "DifftestEndpoint.sv"
    )
    vcs_lua = ctx.linknan_root / "scripts" / "xmake" / "vcs.lua"

    ports = parse_simtop_ports(simtop_sv)
    input_ports = [port for port in ports if port["direction"] == "input"]
    fuzzable_inputs = [port for port in input_ports if port["name"] not in CONTROL_INPUT_NAMES]
    ignored_controls = [port["name"] for port in input_ports if port["name"] in CONTROL_INPUT_NAMES]

    tb_text = read_text(tb_top_v)
    endpoint_text = read_text(endpoint_sv)
    vcs_text = read_text(vcs_lua)

    workload_plusarg_supported = "+workload=" in vcs_text and "$test$plusargs(\"workload\")" in endpoint_text
    workload_plusarg_required = "must set one of `image(-i)`, `imagez(-z)` or `workload(-w)`" in vcs_text
    endpoint_forces_uart_input = "assign difftest_uart_in_ch = 8'hff" in endpoint_text
    top_instantiates_difftest = "DifftestEndpoint difftest" in tb_text

    notes: list[str] = []
    if workload_plusarg_supported:
        notes.append("LinkNan VCS simv-run injects testcase bytes through +workload RAM/ELF loading.")
    if workload_plusarg_required:
        notes.append("xmake simv-run requires image/imagez/workload and always appends +workload for workload mode.")
    if top_instantiates_difftest:
        notes.append("tb_top instantiates DifftestEndpoint as the simulation harness.")
    if endpoint_forces_uart_input:
        notes.append("DifftestEndpoint drives UART input byte as a constant 0xff.")

    pin_stream_driver_supported = False
    raw_supported = bool(fuzzable_inputs) and pin_stream_driver_supported
    if raw_supported:
        reason = "SimTop exposes non-control input ports and the RFuzz pin-stream driver is available."
    elif fuzzable_inputs:
        reason = (
            "SimTop exposes non-control input ports, but no RFuzz VCS pin-stream driver is integrated; "
            "current simv-run still feeds DUT behavior through +workload RAM/ELF images"
        )
    else:
        reason = (
            "current LinkNan VCS SimTop exposes only clock/reset/difftest/log/perf/UART control inputs; "
            "simv-run feeds DUT behavior through +workload RAM/ELF images, not per-cycle top-level fuzzed pins"
        )

    return RfuzzAbiAudit(
        runner_abi="linknan-workload-binary-adapter",
        raw_pin_stream_supported=raw_supported,
        raw_pin_stream_reason=reason,
        top_module="SimTop",
        top_input_pins=sum(int(port["width"]) for port in input_ports),
        fuzzable_input_pins=sum(int(port["width"]) for port in fuzzable_inputs),
        fuzzable_input_names=[str(port["name"]) for port in fuzzable_inputs],
        ignored_control_inputs=ignored_controls,
        pin_stream_driver_supported=pin_stream_driver_supported,
        workload_plusarg_supported=workload_plusarg_supported,
        workload_plusarg_required=workload_plusarg_required,
        validity_supported=False,
        validity_source="none",
        deterministic_reset_supported=False,
        deterministic_reset_model="designer-reset-plus-process-restart; no RFuzz MetaReset transform",
        sparse_memory_supported=False,
        sparse_memory_model="LinkNan RAM/ELF image loader; no RFuzz SparseMem transform",
        notes=notes,
    )
