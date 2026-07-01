from __future__ import annotations

import json
import os
import re
import signal
import shutil
import subprocess
import sys
import time
import hashlib
from contextlib import contextmanager
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
TOHOST_EXIT_TOKEN = "SFUZZ_TOHOST_EXIT"
# riscv-tests place tohost in a dedicated .tohost section at this fixed address;
# used as the fallback when --tohost-addr=auto and a seed has no symbol table.
DEFAULT_TOHOST_ADDR = 0x80001000
SFUZZ_FIRRTL_COV_ENV = "SFUZZ_FIRRTL_COV"
SFUZZ_FIRRTL_COV_OUT_ENV = "SFUZZ_FIRRTL_COV_OUT"
SFUZZ_FIRRTL_COV_PREFIX = "sfuzz_firrtl_coverage"
SFUZZ_FIRRTL_GENERATOR = Path("scripts/linknan/sfuzz_firrtl_cov.py")
EXPECTED_EXPANDED_COMMON_POINTS = 17920
TIMEOUT_GRACE_SEC = 20

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
    sfuzz_core0_staged: bool = False
    sfuzz_core1_staged: bool = False
    sfuzz_core1_executed: bool = False
    sfuzz_core1_handoff_reason: str = ""
    sfuzz_core1_entry: str = ""
    sfuzz_core1_payload_size: int | None = None
    tohost_exit_seen: bool = False
    tohost_exit_code: int | None = None


ASSERTION_REASONS = {"assert_log_nonempty", "assertion_failed"}


def wall_timeout(result: CommandResult) -> bool:
    return bool(result.timed_out)


def design_bug(info: VcsLogInfo) -> bool:
    return bool(info.bug_triggered)


def assertion_failure(info: VcsLogInfo) -> bool:
    return any(reason in ASSERTION_REASONS for reason in info.bug_reasons)


def design_bug_reasons(info: VcsLogInfo) -> list[str]:
    return list(info.bug_reasons)


def classify_infrastructure_error(result: CommandResult, info: VcsLogInfo, run_log: Path) -> str:
    if result.timed_out:
        return ""
    infrastructure_error = result.error
    if result.returncode != 0 and not infrastructure_error and not info.bug_triggered:
        infrastructure_error = f"command returned non-zero exit code {result.returncode}"
    if not run_log.is_file() and not infrastructure_error:
        infrastructure_error = "run.log missing"
    return infrastructure_error


@dataclass
class CoverageResult:
    coverage_name: str = ""
    coverage_value: str = ""
    coverage_source: str = ""
    coverage_status: str = "unavailable"
    bitmap_path: str = ""
    covered: int | None = None
    total: int | None = None


def proc_children(root_pid: int) -> list[int]:
    children_by_parent: dict[int, list[int]] = {}
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            status = (proc / "status").read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        ppid = None
        for line in status.splitlines():
            if line.startswith("PPid:"):
                try:
                    ppid = int(line.split()[1])
                except (IndexError, ValueError):
                    ppid = None
                break
        if ppid is not None:
            children_by_parent.setdefault(ppid, []).append(int(proc.name))

    descendants: list[int] = []
    queue = list(children_by_parent.get(root_pid, []))
    while queue:
        pid = queue.pop(0)
        descendants.append(pid)
        queue.extend(children_by_parent.get(pid, []))
    return descendants


def proc_running(pid: int) -> bool:
    status_path = Path("/proc") / str(pid) / "status"
    try:
        status = status_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    for line in status.splitlines():
        if line.startswith("State:"):
            return "\tZ" not in line and " zombie" not in line.lower()
    return True


def signal_pids(pids: list[int], signo: int, log_file: Any, label: str) -> None:
    seen: set[int] = set()
    for pid in pids:
        if pid in seen or pid <= 1:
            continue
        seen.add(pid)
        try:
            os.kill(pid, signo)
            log_file.write(f"{label}: pid={pid} signal={signo}\n")
        except ProcessLookupError:
            continue
        except PermissionError as exc:
            log_file.write(f"{label}_ERROR: pid={pid} error={exc}\n")


def wait_pids_exit(pids: list[int], timeout_sec: int) -> list[int]:
    deadline = time.monotonic() + timeout_sec
    remaining = sorted(set(pid for pid in pids if pid > 1))
    while remaining and time.monotonic() < deadline:
        remaining = [pid for pid in remaining if proc_running(pid)]
        if remaining:
            time.sleep(0.1)
    return [pid for pid in remaining if proc_running(pid)]


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
    if text.lower() == "sfuzz" or text.lower().startswith("sfuzz.") or text.lower().startswith("sfuzz_"):
        return text
    if text.lower() == "rfuzz" or text.lower().startswith("rfuzz.") or text.lower().startswith("rfuzz_"):
        return text
    if text.lower() == "directfuzz" or text.lower().startswith("directfuzz.") or text.lower().startswith("directfuzz_"):
        return text
    if text.lower() == "surgefuzz" or text.lower().startswith("surgefuzz.") or text.lower().startswith("surgefuzz_"):
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


def simv_compile_command_text(sim_dir: Path) -> str:
    cmd_file = simv_cmd_file(sim_dir)
    text = cmd_file.read_text(encoding="utf-8", errors="replace") if cmd_file.is_file() else ""
    csrc_file = sim_dir / "simv" / "comp" / "csrc.f"
    if csrc_file.is_file():
        text += "\n" + csrc_file.read_text(encoding="utf-8", errors="replace")
    return text


def simv_compiled_without_difftest(sim_dir: Path) -> bool | None:
    cmd_file = simv_cmd_file(sim_dir)
    if not cmd_file.is_file():
        return None
    return "-DCONFIG_NO_DIFFTEST" in simv_compile_command_text(sim_dir)


def requested_firrtl_groups(firrtl_cov: str) -> set[str]:
    normalized = normalize_firrtl_coverage_name(firrtl_cov).lower()
    if normalized in {"firrtl", "firrtl.all", "firrtl.common", "firrtl.sfuzz.firrtl.common.v0"}:
        return {"common"}
    if normalized in {"sfuzz", "sfuzz.native", "sfuzz_native"}:
        return {"sfuzz_native"}
    if normalized in {"rfuzz", "rfuzz.mux", "rfuzz.mux-toggle", "rfuzz.mux_toggle", "rfuzz_mux_toggle"}:
        return {"rfuzz_mux_toggle"}
    if normalized in {
        "directfuzz",
        "directfuzz.mux",
        "directfuzz.mux-toggle",
        "directfuzz.mux_toggle",
        "directfuzz_mux_toggle",
    }:
        return {"directfuzz_mux_toggle"}
    if normalized in {"surgefuzz", "surgefuzz.trace", "surgefuzz.trace-csv", "surgefuzz.trace_csv", "surgefuzz_trace"}:
        return {"surgefuzz_trace"}
    if normalized.startswith("firrtl."):
        suffix = normalized[len("firrtl.") :].replace("-", "_")
        if suffix in {"sfuzz", "sfuzz.native", "sfuzz_native"}:
            return {"sfuzz_native"}
        if suffix.startswith("sfuzz."):
            suffix = suffix[len("sfuzz.") :]
            return {"sfuzz_native"} if suffix == "native" else {f"sfuzz_{suffix}"}
        return {suffix}
    if normalized.startswith("sfuzz."):
        suffix = normalized[len("sfuzz.") :].replace("-", "_")
        return {"sfuzz_native"} if suffix == "native" else {f"sfuzz_{suffix}"}
    if normalized.startswith("rfuzz."):
        return {normalized[len("rfuzz.") :].replace("-", "_")}
    if normalized.startswith("surgefuzz."):
        return {normalized[len("surgefuzz.") :].replace("-", "_")}
    return {normalized} if normalized else set()


def generated_firrtl_metadata(build_dir: Path) -> dict[str, Any] | None:
    path = build_dir / "generated-src" / "sfuzz_firrtl_cover.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as input_file:
        for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
    if "directfuzz_mux_toggle" in requested:
        direct = metadata.get("directfuzz")
        if not isinstance(direct, dict):
            return False
        metadata_path = os.environ.get("SFUZZ_DIRECTFUZZ_METADATA", "")
        if metadata_path:
            config_path = Path(metadata_path).expanduser()
            if not config_path.is_file():
                return False
            if str(direct.get("metadata_sha256", "")) != sha256_file(config_path):
                return False
        target_instance = os.environ.get("SFUZZ_DIRECTFUZZ_TARGET_INSTANCE", "")
        if target_instance and str(direct.get("target_instance", "")) != target_instance:
            return False
        max_distance = os.environ.get("SFUZZ_DIRECTFUZZ_MAX_DISTANCE", "")
        if max_distance and str(direct.get("max_distance", "")) != max_distance:
            return False
    if "surgefuzz_trace" in requested:
        surge = metadata.get("surgefuzz")
        if not isinstance(surge, dict):
            return False
        target_config = os.environ.get("SFUZZ_SURGEFUZZ_TARGET_CONFIG", "")
        if target_config:
            config_path = Path(target_config).expanduser()
            if not config_path.is_file():
                return False
            expected_hash = sha256_file(config_path)
            if str(surge.get("target_config_sha256", "")) != expected_hash:
                return False
            return True
        expected = {
            "module": os.environ.get("SFUZZ_SURGEFUZZ_MODULE", ""),
            "target_instance": os.environ.get("SFUZZ_SURGEFUZZ_TARGET_INSTANCE", ""),
            "target_signal": os.environ.get("SFUZZ_SURGEFUZZ_TARGET", ""),
            "ancestor_selector": os.environ.get("SFUZZ_SURGEFUZZ_ANCESTOR_SELECTOR", ""),
        }
        for key, value in expected.items():
            if value and str(surge.get(key, "")) != value:
                return False
        expected_ancestors = [
            item.strip()
            for item in re.split(r"[,:\s]+", os.environ.get("SFUZZ_SURGEFUZZ_ANCESTORS", ""))
            if item.strip()
        ]
        if expected_ancestors:
            actual = surge.get("ancestors", [])
            actual_names = [str(item.get("name", "")) for item in actual if isinstance(item, dict)]
            if actual_names != expected_ancestors:
                return False
    return True


def firrtl_artifacts_are_not_newer_than_simv(build_dir: Path, simv: Path) -> bool:
    try:
        simv_mtime = simv.stat().st_mtime
    except OSError:
        return False
    artifacts = [
        build_dir / "generated-src" / "firrtl-cover.h",
        build_dir / "generated-src" / "firrtl-cover.cpp",
        build_dir / "rtl" / "verification" / "cover" / "sfuzz_firrtl_cover_bind.sv",
    ]
    for artifact in artifacts:
        try:
            if artifact.is_file() and artifact.stat().st_mtime > simv_mtime:
                return False
        except OSError:
            return False
    return True


def simv_compiled_with_firrtl_coverage(sim_dir: Path, build_dir: Path | None = None, firrtl_cov: str = "") -> bool | None:
    if not simv_cmd_file(sim_dir).is_file():
        return None
    text = simv_compile_command_text(sim_dir)
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
        if not firrtl_artifacts_are_not_newer_than_simv(build_dir, comp_dir / "simv"):
            return False
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


def firrtl_coverage_artifacts_ready(build_dir: Path, firrtl_cov: str) -> bool:
    generated_src = build_dir / "generated-src"
    required = [
        generated_src / "firrtl-cover.h",
        generated_src / "firrtl-cover.cpp",
        build_dir / "rtl" / "verification" / "cover" / "sfuzz_firrtl_cover_bind.sv",
    ]
    return all(path.is_file() for path in required) and generated_firrtl_metadata_matches(build_dir, firrtl_cov)


def build_timeout_sec(args: Any) -> int:
    explicit = int(getattr(args, "build_timeout_sec", 0) or 0)
    return explicit if explicit > 0 else int(getattr(args, "timeout_sec", 0) or 0)


@contextmanager
def file_lock(lock_path: Path, timeout_sec: int = 0):
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_file = lock_path.open("w", encoding="utf-8")
    start = time.monotonic()
    try:
        import fcntl

        while True:
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if timeout_sec > 0 and time.monotonic() - start > timeout_sec:
                    raise TimeoutError(f"timeout waiting for build lock: {lock_path}")
                time.sleep(1.0)
        lock_file.seek(0)
        lock_file.truncate()
        lock_file.write(f"pid={os.getpid()} acquired_at={now_iso()}\n")
        lock_file.flush()
        yield
    finally:
        try:
            import fcntl

            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        finally:
            lock_file.close()


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
            process = subprocess.Popen(
                command,
                cwd=cwd,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
                start_new_session=True,
            )
            returncode = process.wait(timeout=timeout_sec if timeout_sec > 0 else None)
            timed_out = False
            error = ""
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            error = f"timeout after {timeout_sec} seconds"
            returncode = 124
            child_pids = proc_children(process.pid)
            log_file.write(f"\nTIMEOUT: {error}; sending SIGTERM to process group\n")
            if child_pids:
                log_file.write(f"TIMEOUT_CHILDREN: {' '.join(str(pid) for pid in child_pids)}\n")
            log_file.flush()
            try:
                os.killpg(process.pid, signal.SIGTERM)
                signal_pids(child_pids, signal.SIGTERM, log_file, "TIMEOUT_CHILD_SIGTERM")
                remaining = wait_pids_exit(child_pids, TIMEOUT_GRACE_SEC)
                if remaining:
                    log_file.write(f"TIMEOUT_ORPHANED_CHILDREN_AFTER_TERM: {' '.join(str(pid) for pid in remaining)}\n")
                    signal_pids(remaining, signal.SIGTERM, log_file, "TIMEOUT_ORPHAN_SIGTERM")
                    remaining = wait_pids_exit(remaining, 5)
                if remaining:
                    log_file.write(f"TIMEOUT_ORPHAN_TERM_GRACE_EXPIRED: {' '.join(str(pid) for pid in remaining)}\n")
                    signal_pids(remaining, signal.SIGKILL, log_file, "TIMEOUT_ORPHAN_SIGKILL")
                    remaining = wait_pids_exit(remaining, 2)
                returncode = process.wait(timeout=1)
                log_file.write(f"TIMEOUT_GRACEFUL_EXIT: returncode={returncode}\n")
                if remaining:
                    log_file.write(f"TIMEOUT_ORPHANED_CHILDREN_AFTER_KILL: {' '.join(str(pid) for pid in remaining)}\n")
            except (ProcessLookupError, PermissionError) as signal_error:
                log_file.write(f"TIMEOUT_SIGNAL_ERROR: {signal_error}\n")
            except subprocess.TimeoutExpired:
                remaining = proc_children(process.pid) + child_pids
                log_file.write(f"TIMEOUT_SIGTERM_GRACE_EXPIRED: {TIMEOUT_GRACE_SEC} seconds; sending SIGKILL\n")
                log_file.flush()
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                    signal_pids(remaining, signal.SIGKILL, log_file, "TIMEOUT_CHILD_SIGKILL")
                except (ProcessLookupError, PermissionError) as signal_error:
                    log_file.write(f"TIMEOUT_SIGKILL_ERROR: {signal_error}\n")
                returncode = process.wait()
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
    timeout = build_timeout_sec(args)
    with file_lock(ctx.sim_dir / "simv" / "comp" / ".sfuzz_build.lock", timeout):
        build_simv_if_needed_locked(args, ctx, work_dir)


def build_simv_if_needed_locked(args: Any, ctx: VcsContext, work_dir: Path) -> None:
    comp_dir = ctx.sim_dir / "simv" / "comp"
    simv = comp_dir / "simv"
    firrtl_cov = requested_firrtl_coverage(args)
    if getattr(args, "skip_build", False):
        require_file(simv)
        if not ctx.build_no_diff and simv_compiled_without_difftest(ctx.sim_dir) is True:
            raise RuntimeError(
                "existing simv was built with CONFIG_NO_DIFFTEST, which disables the LinkNan trap/commit ABI "
                "needed for natural XSTrap termination; rebuild without xmake simv --no_diff "
                "or set VCS_BUILD_NO_DIFF=1 when intentionally accepting timeout-only sampling"
            )
        if firrtl_cov and simv_compiled_with_firrtl_coverage(ctx.sim_dir, ctx.build_dir, firrtl_cov) is not True:
            raise RuntimeError(
                f"existing simv was not built with SFuzz FIRRTL coverage; rebuild with {SFUZZ_FIRRTL_COV_ENV}={firrtl_cov}"
            )
        return
    needs_firrtl_rebuild = firrtl_cov and simv_compiled_with_firrtl_coverage(ctx.sim_dir, ctx.build_dir, firrtl_cov) is not True
    needs_difftest_rebuild = not ctx.build_no_diff and simv_compiled_without_difftest(ctx.sim_dir) is True
    if (
        simv.is_file()
        and not getattr(args, "build", False)
        and not getattr(args, "rebuild_comp", False)
        and not needs_firrtl_rebuild
        and not needs_difftest_rebuild
    ):
        return
    if shutil.which("xmake") is None:
        raise FileNotFoundError("missing required tool: xmake")
    if shutil.which("vcs") is None:
        raise FileNotFoundError("missing required tool: vcs")
    if (
        firrtl_cov
        and not getattr(args, "build_chisel", False)
        and not firrtl_coverage_artifacts_ready(ctx.build_dir, firrtl_cov)
    ):
        ensure_firrtl_coverage_artifacts(firrtl_cov, ctx, work_dir, build_timeout_sec(args))

    command = [
        "xmake",
        "simv",
        f"--noc={num_cores_to_noc(ctx.num_cores)}",
        f"--sim_dir={ctx.sim_dir}",
        f"--build_dir={ctx.build_dir}",
    ]
    if not getattr(args, "build_chisel", False):
        command.append("--no_build_chisel")
    if ctx.build_no_diff:
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

    result = run_command(command, ctx.linknan_root, work_dir / "logs" / "build_simv.log", build_timeout_sec(args))
    if result.returncode != 0:
        raise RuntimeError(f"xmake simv failed with code {result.returncode}; see {result.command_log_path}")
    require_file(simv)


def read_elf_symbol(path: Path, name: str) -> int | None:
    """Return the value of ELF symbol ``name``, or None if absent/not an ELF.

    Minimal ELF32/ELF64 (little/big-endian) symbol-table reader; no external
    dependency. Used to locate ``tohost`` in riscv-test workloads so the HTIF
    completion monitor knows which address to watch.
    """
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return None
    is64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    import struct

    def u(fmt: str, off: int) -> int:
        return struct.unpack_from(endian + fmt, data, off)[0]

    try:
        if is64:
            e_shoff = u("Q", 0x28)
            e_shentsize = u("H", 0x3A)
            e_shnum = u("H", 0x3C)
        else:
            e_shoff = u("I", 0x20)
            e_shentsize = u("H", 0x2E)
            e_shnum = u("H", 0x30)
        if e_shoff == 0 or e_shnum == 0:
            return None
        target = name.encode("utf-8")
        for i in range(e_shnum):
            sh = e_shoff + i * e_shentsize
            sh_type = u("I", sh + 4)
            if sh_type != 2:  # SHT_SYMTAB
                continue
            sh_offset = u("Q", sh + 0x18) if is64 else u("I", sh + 0x10)
            sh_size = u("Q", sh + 0x20) if is64 else u("I", sh + 0x14)
            sh_link = u("I", sh + 0x28) if is64 else u("I", sh + 0x18)
            sh_entsize = u("Q", sh + 0x38) if is64 else u("I", sh + 0x24)
            if sh_entsize == 0:
                continue
            str_sh = e_shoff + sh_link * e_shentsize
            str_off = u("Q", str_sh + 0x18) if is64 else u("I", str_sh + 0x10)
            for s in range(sh_offset, sh_offset + sh_size, sh_entsize):
                st_name = u("I", s)
                if is64:
                    st_value = u("Q", s + 8)
                else:
                    st_value = u("I", s + 4)
                end = data.index(b"\x00", str_off + st_name)
                if data[str_off + st_name : end] == target:
                    return st_value
    except (struct.error, ValueError, IndexError):
        return None
    return None


def resolve_tohost_addr(spec: str | None, seeds: list[Path]) -> int:
    """Resolve the HTIF tohost monitor address from a CLI spec.

    spec: "off"/"none"/"0" disables (returns 0); a hex/decimal literal sets it
    explicitly; "auto" (default) reads ``tohost`` from the first ELF seed and
    falls back to DEFAULT_TOHOST_ADDR if a seed is an ELF but lacks the symbol.
    Returns 0 when no seed is an ELF (monitor stays off, behavior unchanged).
    """
    text = (spec or "auto").strip().lower()
    if text in {"off", "none", "0", ""}:
        return 0
    if text != "auto":
        return int(text, 0)
    saw_elf = False
    for seed in seeds:
        try:
            if seed.read_bytes()[:4] != b"\x7fELF":
                continue
        except OSError:
            continue
        saw_elf = True
        addr = read_elf_symbol(seed, "tohost")
        if addr:
            return addr
    return DEFAULT_TOHOST_ADDR if saw_elf else 0


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
    tohost_addr: int = 0,
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
    # HTIF tohost completion monitor: a single +plusarg passed through simv_args.
    # 0 keeps it off, so existing workloads are unaffected.
    if tohost_addr > 0:
        plusarg = f"+tohost-addr={tohost_addr}"
        simv_args = f"{simv_args} {plusarg}".strip() if simv_args else plusarg
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
        if TOHOST_EXIT_TOKEN in line:
            info.tohost_exit_seen = True
            code_match = re.search(r"SFUZZ_TOHOST_EXIT:\s+core=\d+\s+code=(-?\d+)", line)
            if code_match:
                info.tohost_exit_code = int(code_match.group(1))
        for reason, pattern in BUG_PATTERNS:
            if pattern.search(line) and reason not in info.bug_reasons:
                info.bug_reasons.append(reason)
        payload_match = re.search(r"SFUZZ_CORE_PAYLOAD:\s+name=(\S+)\s+paddr=(0x[0-9a-fA-F]+)\s+size=(\d+)", line)
        if payload_match:
            core_name = payload_match.group(1)
            if core_name == "core0":
                info.sfuzz_core0_staged = True
            elif core_name == "core1":
                info.sfuzz_core1_staged = True
                info.sfuzz_core1_entry = payload_match.group(2)
                info.sfuzz_core1_payload_size = int(payload_match.group(3))
        handoff_match = re.search(
            r"SFUZZ_CORE1_HANDOFF:\s+staged=(\d+)\s+entry=(0x[0-9a-fA-F]+)\s+size=(\d+)\s+executed=(\d+)\s+reason=(\S+)",
            line,
        )
        if handoff_match:
            info.sfuzz_core1_staged = handoff_match.group(1) != "0"
            info.sfuzz_core1_entry = handoff_match.group(2)
            info.sfuzz_core1_payload_size = int(handoff_match.group(3))
            handoff_executed = handoff_match.group(4) != "0"
            info.sfuzz_core1_executed = info.sfuzz_core1_executed or handoff_executed
            if handoff_executed or not info.sfuzz_core1_handoff_reason:
                info.sfuzz_core1_handoff_reason = handoff_match.group(5)
        executed_match = re.search(r"SFUZZ_CORE_EXECUTED:\s+core=(\d+)\s+instrCnt=(\d+)\s+pc=(0x[0-9a-fA-F]+)", line)
        if executed_match and executed_match.group(1) == "1":
            info.sfuzz_core1_executed = True
            info.sfuzz_core1_handoff_reason = "core1_instr_count"

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
    candidates = [
        case_dir / f"{SFUZZ_FIRRTL_COV_PREFIX}.json",
        case_dir / "sfuzz_native_coverage.json",
        case_dir / "rfuzz_toggle_bitmap.json",
        case_dir / "directfuzz_coverage.json",
        case_dir / "surgefuzz_trace.json",
    ]
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
