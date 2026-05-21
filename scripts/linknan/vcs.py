from __future__ import annotations

import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .common import now_iso, require_file
from .config import VcsContext


VCS_REPORT_TOKEN = "V C S   S i m u l a t i o n   R e p o r t"
VCS_REPORT_NORMALIZED = "VCSSimulationReport"
SFUZ_EXPANSION_TOKEN = "SFuzz structured seed detected. Expanding image into RAM"
GOOD_TRAP_TOKEN = "HIT GOOD TRAP"

BUG_PATTERNS = [
    ("hit_bad_trap", re.compile(r"HIT BAD TRAP", re.IGNORECASE)),
    ("unknown_trap_code", re.compile(r"Unknown trap code", re.IGNORECASE)),
    ("difftest_mismatch", re.compile(r"different at pc", re.IGNORECASE)),
    ("no_commit_stuck", re.compile(r"No instruction of core .* commits .* maybe get stuck", re.IGNORECASE)),
    ("assertion_failed", re.compile(r"Assertion failed", re.IGNORECASE)),
    ("fatal", re.compile(r"\bFatal\b|\$fatal", re.IGNORECASE)),
]

COVERAGE_PATTERNS = [
    ("vcs_overall_coverage", re.compile(r"\bOverall\s+Coverage\b[^0-9]*(\d+(?:\.\d+)?)\s*%?", re.IGNORECASE)),
    ("vcs_total_coverage", re.compile(r"\bTotal\s+Coverage\b[^0-9]*(\d+(?:\.\d+)?)\s*%?", re.IGNORECASE)),
    ("vcs_score", re.compile(r"\bScore\b[^0-9]*(\d+(?:\.\d+)?)\s*%?", re.IGNORECASE)),
]


@dataclass
class CommandResult:
    command: list[str]
    returncode: int
    command_log_path: str
    wall_time_sec: float
    timed_out: bool = False
    error: str = ""


@dataclass
class VcsLogInfo:
    vcs_report_seen: bool = False
    sfuz_expansion_seen: bool = False
    good_trap_seen: bool = False
    bug_triggered: bool = False
    bug_reasons: list[str] = field(default_factory=list)
    cycles: int | None = None
    cycles_are_requested_only: bool = False
    vcs_sim_time_ps: int | None = None
    vcs_cpu_time_sec: float | None = None


@dataclass
class CoverageResult:
    coverage_name: str = ""
    coverage_value: str = ""
    coverage_source: str = ""
    coverage_status: str = "unavailable"


def num_cores_to_noc(num_cores: str) -> str:
    table = {"1": "small", "2": "reduced", "4": "full"}
    if num_cores not in table:
        raise ValueError(f"unsupported NUM_CORES for LinkNan xmake: {num_cores}")
    return table[num_cores]


def run_command(command: list[str], cwd: Path, log_path: Path, timeout_sec: int = 0) -> CommandResult:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    with log_path.open("w", encoding="utf-8", errors="replace") as log_file:
        log_file.write(f"COMMAND: {' '.join(command)}\n")
        log_file.write(f"START: {now_iso()}\n\n")
        log_file.flush()
        try:
            process = subprocess.run(
                command,
                cwd=cwd,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout_sec if timeout_sec > 0 else None,
            )
            returncode = process.returncode
            timed_out = False
            error = ""
        except subprocess.TimeoutExpired as exc:
            returncode = 124
            timed_out = True
            error = f"timeout after {timeout_sec} seconds"
            log_file.write(f"\nTIMEOUT: {error}\n")
            if exc.stdout:
                log_file.write(str(exc.stdout))
            if exc.stderr:
                log_file.write(str(exc.stderr))
        wall_time = time.monotonic() - start
        log_file.write(f"\nEND: {now_iso()}\n")
        log_file.write(f"RETURNCODE: {returncode}\n")
    return CommandResult(
        command=command,
        returncode=returncode,
        command_log_path=str(log_path),
        wall_time_sec=wall_time,
        timed_out=timed_out,
        error=error,
    )


def build_simv_if_needed(args: Any, ctx: VcsContext, work_dir: Path) -> None:
    comp_dir = ctx.sim_dir / "simv" / "comp"
    simv = comp_dir / "simv"
    if getattr(args, "skip_build", False):
        require_file(simv)
        return
    if simv.is_file() and not getattr(args, "build", False) and not getattr(args, "rebuild_comp", False):
        return
    if shutil.which("xmake") is None:
        raise FileNotFoundError("missing required tool: xmake")
    if shutil.which("vcs") is None:
        raise FileNotFoundError("missing required tool: vcs")

    command = [
        "xmake",
        "simv",
        "--no_build_chisel",
        f"--noc={num_cores_to_noc(ctx.num_cores)}",
        f"--sim_dir={ctx.sim_dir}",
        f"--build_dir={ctx.build_dir}",
    ]
    if ctx.no_diff:
        command.append("--no_diff")
    if ctx.no_fsdb:
        command.append("--no_fsdb")
    if ctx.no_xprop:
        command.append("--no_xprop")
    if ctx.no_fgp:
        command.append("--no_fgp")
    if ctx.no_initreg_random:
        command.append("--no_initreg_random")
    if getattr(args, "cov", False):
        command.append("--cov")
    if getattr(args, "rebuild_comp", False):
        command.append("--rebuild_comp")

    result = run_command(command, ctx.linknan_root, work_dir / "logs" / "build_simv.log", getattr(args, "timeout_sec", 0))
    if result.returncode != 0:
        raise RuntimeError(f"xmake simv failed with code {result.returncode}; see {result.command_log_path}")
    require_file(simv)


def run_vcs_seed(
    *,
    seed: Path,
    case_name: str,
    runs_dir: Path,
    logs_dir: Path,
    ctx: VcsContext,
    timeout_sec: int = 0,
    cov: bool = False,
    simv_args: str | None = None,
) -> tuple[CommandResult, Path, Path, Path]:
    case_dir = runs_dir / case_name
    if case_dir.exists():
        shutil.rmtree(case_dir)
    command = [
        "xmake",
        "simv-run",
        f"--workload={seed}",
        f"--cycles={ctx.cycles}",
        f"--case_name={case_name}",
        f"--sim_dir={ctx.sim_dir}",
        f"--run_dir={runs_dir}",
    ]
    if ctx.no_diff:
        command.append("--no_diff")
    if ctx.no_fsdb:
        command.append("--no_dump")
    if ctx.no_fgp:
        command.append("--no_fgp")
    if cov:
        command.append("--cov")
    if simv_args:
        command.append(f"--simv_args={simv_args}")
    result = run_command(command, ctx.linknan_root, logs_dir / f"{case_name}.command.log", timeout_sec)
    return result, case_dir, case_dir / "run.log", case_dir / "assert.log"


def scan_vcs_logs(run_log: Path, assert_log: Path, requested_cycles: int) -> VcsLogInfo:
    info = VcsLogInfo()
    if assert_log.is_file() and assert_log.stat().st_size > 0:
        info.bug_reasons.append("assert_log_nonempty")
    if not run_log.is_file():
        info.bug_reasons.append("run_log_missing")
        info.bug_triggered = True
        return info

    text = run_log.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        normalized = re.sub(r"\s+", "", line)
        if VCS_REPORT_NORMALIZED in normalized:
            info.vcs_report_seen = True
        if SFUZ_EXPANSION_TOKEN in line:
            info.sfuz_expansion_seen = True
        if GOOD_TRAP_TOKEN in line:
            info.good_trap_seen = True
        for reason, pattern in BUG_PATTERNS:
            if pattern.search(line) and reason not in info.bug_reasons:
                info.bug_reasons.append(reason)

    exceeded = [int(match) for match in re.findall(r"EXCEEDED MAX CYCLE:\s*(\d+)", text)]
    if exceeded:
        info.cycles = exceeded[-1]
    sim_time = re.findall(r"\bTime:\s*(\d+)\s*ps\b", text)
    if sim_time:
        info.vcs_sim_time_ps = int(sim_time[-1])
    cpu_time = re.findall(r"\bCPU Time:\s*([0-9]+(?:\.[0-9]+)?)\s*seconds", text)
    if cpu_time:
        info.vcs_cpu_time_sec = float(cpu_time[-1])
    if info.cycles is None and requested_cycles:
        info.cycles = requested_cycles
        info.cycles_are_requested_only = True
    info.bug_triggered = bool(info.bug_reasons)
    return info


def find_vdb_dirs(case_dir: Path, sim_dir: Path) -> list[Path]:
    candidates: list[Path] = []
    for base in [case_dir, sim_dir / "simv" / "comp"]:
        if base.exists():
            candidates.extend(path for path in base.rglob("*.vdb") if path.is_dir())
    unique: list[Path] = []
    seen: set[Path] = set()
    for path in candidates:
        resolved = path.resolve()
        if resolved not in seen:
            unique.append(path)
            seen.add(resolved)
    return unique


def simv_compiled_with_coverage(sim_dir: Path) -> bool | None:
    cmd_file = sim_dir / "simv" / "comp" / "vcs_cmd.sh"
    if not cmd_file.is_file():
        return None
    text = cmd_file.read_text(encoding="utf-8", errors="replace")
    return bool(re.search(r"(^|\s)-cm\s+\S+", text))


def parse_coverage_from_text(path: Path) -> CoverageResult | None:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as text_file:
            for line in text_file:
                for name, pattern in COVERAGE_PATTERNS:
                    match = pattern.search(line)
                    if match:
                        return CoverageResult(
                            coverage_name=name,
                            coverage_value=match.group(1),
                            coverage_source=str(path),
                            coverage_status="parsed",
                        )
    except OSError:
        return None
    return None


def collect_vcs_coverage(args: Any, case_dir: Path, sim_dir: Path) -> CoverageResult:
    vdb_dirs = find_vdb_dirs(case_dir, sim_dir)
    if not vdb_dirs:
        status = "unavailable: no VCS .vdb found"
        if not getattr(args, "cov", False):
            status += "; compile and run with --cov to request VCS coverage"
        elif simv_compiled_with_coverage(sim_dir) is False:
            status += "; current simv compile command lacks -cm, rebuild with xmake simv --cov"
        return CoverageResult(coverage_status=status)
    if not getattr(args, "run_urg", False):
        return CoverageResult(
            coverage_name="vcs_vdb",
            coverage_value="present",
            coverage_source=";".join(str(path) for path in vdb_dirs),
            coverage_status="vdb_found: pass --run-urg to parse a text summary",
        )
    if shutil.which("urg") is None:
        return CoverageResult(
            coverage_name="vcs_vdb",
            coverage_value="present",
            coverage_source=";".join(str(path) for path in vdb_dirs),
            coverage_status="vdb_found: urg not found",
        )

    report_dir = case_dir / "urgReport"
    if report_dir.exists():
        shutil.rmtree(report_dir)
    command = ["urg"]
    for vdb in vdb_dirs:
        command.extend(["-dir", str(vdb)])
    command.extend(["-format", "text", "-report", str(report_dir)])
    result = run_command(command, case_dir, case_dir / "urg.log", 0)
    if result.returncode != 0:
        return CoverageResult(
            coverage_name="vcs_vdb",
            coverage_value="present",
            coverage_source=";".join(str(path) for path in vdb_dirs),
            coverage_status=f"urg_failed: see {result.command_log_path}",
        )
    for text_path in sorted(report_dir.rglob("*")):
        if text_path.is_file():
            parsed = parse_coverage_from_text(text_path)
            if parsed is not None:
                return parsed
    return CoverageResult(
        coverage_name="vcs_vdb",
        coverage_value="present",
        coverage_source=str(report_dir),
        coverage_status="urg_report_generated_no_overall_value_found",
    )
