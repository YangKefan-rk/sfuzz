from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
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
FINISH_TOKEN = "$finish"
SFUZZ_FIRRTL_COV_ENV = "SFUZZ_FIRRTL_COV"
SFUZZ_FIRRTL_COV_OUT_ENV = "SFUZZ_FIRRTL_COV_OUT"
SFUZZ_FIRRTL_COV_PREFIX = "sfuzz_firrtl_coverage"
SFUZZ_FIRRTL_GENERATOR = Path("scripts/linknan/sfuzz_firrtl_cov.py")
EXPECTED_EXPANDED_COMMON_POINTS = 17920

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
    finish_seen: bool = False
    bug_triggered: bool = False
    bug_reasons: list[str] = field(default_factory=list)
    max_cycle_exceeded: bool = False
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
    bitmap_path: str = ""
    covered: int | None = None
    total: int | None = None


def num_cores_to_noc(num_cores: str) -> str:
    table = {"1": "small", "2": "reduced", "4": "full"}
    if num_cores not in table:
        raise ValueError(f"unsupported NUM_CORES for LinkNan xmake: {num_cores}")
    return table[num_cores]


def normalize_firrtl_coverage_name(value: str | None) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    if text.lower() == "firrtl" or text.lower().startswith("firrtl."):
        return text
    return f"FIRRTL.{text}"


def requested_firrtl_coverage(args: Any) -> str:
    return normalize_firrtl_coverage_name(
        getattr(args, "firrtl_cov", None)
        or getattr(args, "sfuzz_firrtl_cov", None)
        or os.environ.get(SFUZZ_FIRRTL_COV_ENV)
    )


def simv_cmd_file(sim_dir: Path) -> Path:
    return sim_dir / "simv" / "comp" / "vcs_cmd.sh"


def requested_firrtl_groups(firrtl_cov: str) -> set[str]:
    normalized = normalize_firrtl_coverage_name(firrtl_cov).lower()
    if normalized in {"firrtl", "firrtl.all", "firrtl.common", "firrtl.sfuzz.firrtl.common.v0"}:
        return {"common"}
    if normalized.startswith("firrtl."):
        return {normalized[len("firrtl.") :]}
    return {normalized} if normalized else set()


def generated_firrtl_metadata(build_dir: Path) -> dict[str, Any] | None:
    path = build_dir / "generated-src" / "sfuzz_firrtl_cover.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None


def generated_firrtl_metadata_matches(build_dir: Path, firrtl_cov: str) -> bool:
    metadata = generated_firrtl_metadata(build_dir)
    if not metadata or metadata.get("backend") != "sfuzz_firrtl_sv_bind":
        return False
    groups = metadata.get("groups")
    if not isinstance(groups, dict):
        return False
    requested = requested_firrtl_groups(firrtl_cov)
    if not requested:
        return True
    for group in requested:
        if group not in groups:
            return False
        try:
            count = int(groups[group])
        except (TypeError, ValueError):
            return False
        if count <= 0:
            return False
        if group in {"common", "all"} and count < EXPECTED_EXPANDED_COMMON_POINTS:
            return False
    return True


def simv_compiled_with_firrtl_coverage(sim_dir: Path, build_dir: Path | None = None, firrtl_cov: str = "") -> bool | None:
    cmd_file = simv_cmd_file(sim_dir)
    if not cmd_file.is_file():
        return None
    text = cmd_file.read_text(encoding="utf-8", errors="replace")
    csrc_file = sim_dir / "simv" / "comp" / "csrc.f"
    if csrc_file.is_file():
        text += "\n" + csrc_file.read_text(encoding="utf-8", errors="replace")
    if "-DFIRRTL_COVER" not in text or "sfuzz_firrtl_cov_export.cpp" not in text:
        return False

    comp_dir = sim_dir / "simv" / "comp"
    binaries = [comp_dir / "simv"]
    daidir = comp_dir / "simv.daidir"
    if daidir.is_dir():
        binaries.extend(sorted(daidir.glob("*.so")))
    marker = b"SFUZZ_FIRRTL_COVERAGE"
    marker_found = False
    for binary in binaries:
        try:
            if binary.is_file() and marker in binary.read_bytes():
                marker_found = True
                break
        except OSError:
            continue
    if not marker_found:
        return False

    if firrtl_cov and build_dir is not None:
        return generated_firrtl_metadata_matches(build_dir, firrtl_cov)
    return True


def ensure_firrtl_coverage_artifacts(firrtl_cov: str, ctx: VcsContext, work_dir: Path, timeout_sec: int = 0) -> None:
    generated_src = ctx.build_dir / "generated-src"
    required = [
        generated_src / "firrtl-cover.h",
        generated_src / "firrtl-cover.cpp",
        ctx.build_dir / "rtl" / "verification" / "cover" / "sfuzz_firrtl_cover_bind.sv",
    ]

    generator = ctx.linknan_root / SFUZZ_FIRRTL_GENERATOR
    if not generator.is_file():
        missing = ", ".join(str(path) for path in required if not path.is_file())
        raise RuntimeError(
            f"missing SFuzz FIRRTL coverage artifacts ({missing}) and generator is not available: {generator}"
        )
    rtl_dir = ctx.build_dir / "rtl"
    if not rtl_dir.is_dir():
        raise RuntimeError(f"cannot generate SFuzz FIRRTL coverage artifacts; RTL directory does not exist: {rtl_dir}")

    command = [
        sys.executable,
        str(generator),
        str(rtl_dir),
        "--generated-src-dir",
        str(generated_src),
        "--groups",
        firrtl_cov,
    ]
    result = run_command(
        command,
        ctx.linknan_root,
        work_dir / "logs" / "generate_firrtl_coverage.log",
        timeout_sec,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"SFuzz FIRRTL coverage generation failed with code {result.returncode}; see {result.command_log_path}"
        )
    for path in required:
        require_file(path)


def run_command(
    command: list[str],
    cwd: Path,
    log_path: Path,
    timeout_sec: int = 0,
    extra_env: dict[str, str] | None = None,
) -> CommandResult:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    with log_path.open("w", encoding="utf-8", errors="replace") as log_file:
        log_file.write(f"COMMAND: {' '.join(command)}\n")
        log_file.write(f"START: {now_iso()}\n\n")
        log_file.flush()
        env = None
        if extra_env:
            env = os.environ.copy()
            env.update(extra_env)
            for key, value in sorted(extra_env.items()):
                log_file.write(f"ENV: {key}={value}\n")
            log_file.write("\n")
            log_file.flush()
        try:
            process = subprocess.run(
                command,
                cwd=cwd,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout_sec if timeout_sec > 0 else None,
                env=env,
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
    firrtl_cov = requested_firrtl_coverage(args)
    if getattr(args, "skip_build", False):
        require_file(simv)
        if firrtl_cov and simv_compiled_with_firrtl_coverage(ctx.sim_dir, ctx.build_dir, firrtl_cov) is not True:
            raise RuntimeError(
                f"existing simv was not built with SFuzz FIRRTL coverage; rebuild with {SFUZZ_FIRRTL_COV_ENV}={firrtl_cov}"
            )
        return
    needs_firrtl_rebuild = firrtl_cov and simv_compiled_with_firrtl_coverage(ctx.sim_dir, ctx.build_dir, firrtl_cov) is not True
    if (
        simv.is_file()
        and not getattr(args, "build", False)
        and not getattr(args, "rebuild_comp", False)
        and not needs_firrtl_rebuild
    ):
        return
    if shutil.which("xmake") is None:
        raise FileNotFoundError("missing required tool: xmake")
    if shutil.which("vcs") is None:
        raise FileNotFoundError("missing required tool: vcs")
    if firrtl_cov:
        ensure_firrtl_coverage_artifacts(firrtl_cov, ctx, work_dir, getattr(args, "timeout_sec", 0))

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
    if firrtl_cov:
        command.append(f"--firrtl_cov={firrtl_cov}")
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
    extra_env: dict[str, str] | None = None,
) -> tuple[CommandResult, Path, Path, Path]:
    case_dir = runs_dir / case_name
    if case_dir.exists():
        shutil.rmtree(case_dir)
    command = [
        "xmake",
        "simv-run",
        f"--workload={seed}",
        f"--case_name={case_name}",
        f"--sim_dir={ctx.sim_dir}",
        f"--run_dir={runs_dir}",
    ]
    if ctx.cycles is not None and ctx.cycles > 0:
        command.append(f"--cycles={ctx.cycles}")
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
    result = run_command(command, ctx.linknan_root, logs_dir / f"{case_name}.command.log", timeout_sec, extra_env)
    return result, case_dir, case_dir / "run.log", case_dir / "assert.log"


def scan_vcs_logs(run_log: Path, assert_log: Path, requested_cycles: int | None) -> VcsLogInfo:
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
        if FINISH_TOKEN in line:
            info.finish_seen = True
        for reason, pattern in BUG_PATTERNS:
            if pattern.search(line) and reason not in info.bug_reasons:
                info.bug_reasons.append(reason)

    exceeded = [int(match) for match in re.findall(r"EXCEEDED MAX CYCLE:\s*(\d+)", text)]
    if exceeded:
        info.cycles = exceeded[-1]
        info.max_cycle_exceeded = True
    sim_time = re.findall(r"\bTime:\s*(\d+)\s*ps\b", text)
    if sim_time:
        info.vcs_sim_time_ps = int(sim_time[-1])
    cpu_time = re.findall(r"\bCPU Time:\s*([0-9]+(?:\.[0-9]+)?)\s*seconds", text)
    if cpu_time:
        info.vcs_cpu_time_sec = float(cpu_time[-1])
    if info.cycles is None and requested_cycles is not None:
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
    cmd_file = simv_cmd_file(sim_dir)
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


def sfuzz_firrtl_summary_candidates(case_dir: Path) -> list[Path]:
    candidates = [case_dir / f"{SFUZZ_FIRRTL_COV_PREFIX}.json"]
    out_prefix = os.environ.get(SFUZZ_FIRRTL_COV_OUT_ENV)
    if out_prefix:
        out_summary = Path(f"{out_prefix}.json").expanduser()
        if not out_summary.is_absolute():
            out_summary = case_dir / out_summary
        candidates.append(out_summary)
    if case_dir.exists():
        candidates.extend(sorted(case_dir.rglob(f"{SFUZZ_FIRRTL_COV_PREFIX}.json")))

    unique: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve() if candidate.exists() else candidate.absolute()
        if resolved not in seen:
            unique.append(candidate)
            seen.add(resolved)
    return unique


def parse_sfuzz_firrtl_coverage(path: Path) -> CoverageResult | None:
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as exc:
        return CoverageResult(
            coverage_name="sfuzz_firrtl",
            coverage_source=str(path),
            coverage_status=f"unavailable: invalid SFuzz FIRRTL coverage json: {exc}",
        )

    if payload.get("backend") != "sfuzz_firrtl":
        return None

    try:
        total = int(payload.get("total", 0))
        covered = int(payload.get("covered", 0))
        percent = float(payload.get("coverage_percent", 0.0))
    except (TypeError, ValueError) as exc:
        return CoverageResult(
            coverage_name="sfuzz_firrtl",
            coverage_source=str(path),
            coverage_status=f"unavailable: invalid SFuzz FIRRTL numeric fields: {exc}",
        )

    bitmap_raw = str(payload.get("bitmap_file") or f"{SFUZZ_FIRRTL_COV_PREFIX}.bin")
    bitmap_path = Path(bitmap_raw)
    if not bitmap_path.is_absolute():
        bitmap_path = path.parent / bitmap_path

    status = "parsed_sfuzz_firrtl"
    source = str(path)
    if bitmap_path.is_file():
        source = f"{path};{bitmap_path}"
        bitmap_size = bitmap_path.stat().st_size
        if total and bitmap_size != total:
            status += f": bitmap_size={bitmap_size} total={total}"
    else:
        status += ": bitmap_missing"

    group = str(payload.get("group") or payload.get("coverage_name") or "FIRRTL")
    return CoverageResult(
        coverage_name=f"sfuzz_firrtl.{group}",
        coverage_value=f"{percent:.6f}",
        coverage_source=source,
        coverage_status=f"{status}: covered={covered} total={total}",
        bitmap_path=str(bitmap_path) if bitmap_path.is_file() else "",
        covered=covered,
        total=total,
    )


def collect_sfuzz_firrtl_coverage(case_dir: Path) -> CoverageResult | None:
    for candidate in sfuzz_firrtl_summary_candidates(case_dir):
        parsed = parse_sfuzz_firrtl_coverage(candidate)
        if parsed is not None:
            return parsed
    return None


def common_coverage_backend(coverage: CoverageResult) -> str:
    if coverage.coverage_name.startswith("sfuzz_firrtl."):
        return "sfuzz_firrtl"
    if coverage.coverage_name == "vcs_vdb" or coverage.coverage_status.startswith("parsed"):
        return "vcs_builtin"
    return "none"


def collect_vcs_coverage(args: Any, case_dir: Path, sim_dir: Path) -> CoverageResult:
    firrtl_coverage = collect_sfuzz_firrtl_coverage(case_dir)
    if firrtl_coverage is not None:
        return firrtl_coverage
    firrtl_request = requested_firrtl_coverage(args)
    if firrtl_request:
        return CoverageResult(
            coverage_name="sfuzz_firrtl",
            coverage_status=(
                f"unavailable: no SFuzz FIRRTL coverage json found for {firrtl_request}; "
                "check that simv was built with --firrtl_cov and the seed run reached coverage export"
            ),
        )

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
