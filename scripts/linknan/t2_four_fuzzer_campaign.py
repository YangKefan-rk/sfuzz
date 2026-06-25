#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import shlex
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from linknan.common import require_file, write_table  # noqa: E402
from linknan.config import DEFAULT_CONFIG, SFUZZ_HOME  # noqa: E402


CAMPAIGN_FIELDS = [
    "method",
    "worker_id",
    "command",
    "env",
    "work_dir",
    "output_csv",
    "output_json",
    "coverage_name",
    "formal_guard",
    "seed_list",
]
SUMMARY_FIELDS = [
    "method",
    "result_csv",
    "rows",
    "mutation_rows",
    "mutation_ratio",
    "paper_faithful_rows",
    "timed_out_rows",
    "bug_rows",
    "no_cycle_limit_rows",
    "command_cycle_violations",
    "final_covered",
    "final_total",
    "final_percent",
    "auc_exec_percent",
    "notes",
]
DEFAULT_DIRECT_TARGET = "SimTop.soc.cc_0.tile.core.memBlock"
ACTIVE_PROCESS_GROUPS: set[int] = set()
ACTIVE_PROCESS_GROUPS_LOCK = threading.Lock()


@dataclass(frozen=True)
class Testcase:
    testcase_id: str
    source: str
    category: str
    sfuzz_seed: Path
    workload: Path
    input_format: str
    file_size: int


@dataclass(frozen=True)
class CampaignPaths:
    root: Path
    inputs: Path
    results: Path
    logs: Path
    reports: Path
    manifests: Path
    scripts: Path

    @classmethod
    def create(cls, root: Path) -> "CampaignPaths":
        paths = cls(
            root=root,
            inputs=root / "inputs",
            results=root / "results",
            logs=root / "logs",
            reports=root / "reports",
            manifests=root / "manifests",
            scripts=root / "scripts",
        )
        for directory in [paths.inputs, paths.results, paths.logs, paths.reports, paths.manifests, paths.scripts]:
            directory.mkdir(parents=True, exist_ok=True)
        return paths


def now_slug() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def resolve_manifest_path(raw: str, manifest: Path) -> Path:
    path = Path(raw).expanduser()
    if path.is_absolute():
        return path
    return (SFUZZ_HOME / path).resolve()


def load_testcases(manifest: Path, limit: int) -> list[Testcase]:
    require_file(manifest)
    rows: list[Testcase] = []
    with manifest.open(newline="", encoding="utf-8") as input_file:
        reader = csv.DictReader(input_file)
        required = {"testcase_id", "source", "category", "sfuzz_seed_path", "input_path", "input_format", "file_size"}
        missing = sorted(required - set(reader.fieldnames or []))
        if missing:
            raise ValueError(f"{manifest}: missing required columns: {', '.join(missing)}")
        for row in reader:
            sfuzz_seed = resolve_manifest_path(row.get("sfuzz_seed_path", ""), manifest)
            workload_raw = row.get("rfuzz_workload_path") or row.get("input_path") or ""
            workload = resolve_manifest_path(workload_raw, manifest)
            if not sfuzz_seed.is_file() or not workload.is_file():
                continue
            rows.append(
                Testcase(
                    testcase_id=str(row["testcase_id"]),
                    source=str(row["source"]),
                    category=str(row["category"]),
                    sfuzz_seed=sfuzz_seed,
                    workload=workload,
                    input_format=str(row["input_format"]),
                    file_size=int(row.get("file_size") or workload.stat().st_size),
                )
            )
            if limit > 0 and len(rows) >= limit:
                break
    if not rows:
        raise ValueError(f"{manifest}: no runnable testcase with both SFUZ seed and workload image")
    return rows


def write_seed_lists(paths: CampaignPaths, testcases: list[Testcase]) -> tuple[Path, Path, Path]:
    seed_lists = paths.inputs / "seed_lists"
    seed_lists.mkdir(parents=True, exist_ok=True)
    sfuzz_list = seed_lists / "sfuzz_seed_list.txt"
    workload_list = seed_lists / "workload_seed_list.txt"
    sfuzz_list.write_text("\n".join(str(case.sfuzz_seed) for case in testcases) + "\n", encoding="utf-8")
    workload_list.write_text("\n".join(str(case.workload) for case in testcases) + "\n", encoding="utf-8")

    manifest_csv = paths.manifests / "selected_testcases.csv"
    with manifest_csv.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(
            output_file,
            fieldnames=["testcase_id", "source", "category", "sfuzz_seed", "workload", "input_format", "file_size"],
        )
        writer.writeheader()
        for case in testcases:
            writer.writerow(
                {
                    "testcase_id": case.testcase_id,
                    "source": case.source,
                    "category": case.category,
                    "sfuzz_seed": case.sfuzz_seed,
                    "workload": case.workload,
                    "input_format": case.input_format,
                    "file_size": case.file_size,
                }
            )
    return sfuzz_list, workload_list, manifest_csv


def write_seed_shards(paths: CampaignPaths, testcases: list[Testcase], workers: int) -> tuple[list[Path], list[Path]]:
    worker_count = max(1, min(workers, len(testcases)))
    seed_lists = paths.inputs / "seed_lists"
    seed_lists.mkdir(parents=True, exist_ok=True)
    sfuzz_shards: list[list[str]] = [[] for _ in range(worker_count)]
    workload_shards: list[list[str]] = [[] for _ in range(worker_count)]
    for index, case in enumerate(testcases):
        shard = index % worker_count
        sfuzz_shards[shard].append(str(case.sfuzz_seed))
        workload_shards[shard].append(str(case.workload))

    sfuzz_paths: list[Path] = []
    workload_paths: list[Path] = []
    for worker_id in range(worker_count):
        sfuzz_path = seed_lists / f"sfuzz_seed_list.worker-{worker_id:03d}.txt"
        workload_path = seed_lists / f"workload_seed_list.worker-{worker_id:03d}.txt"
        sfuzz_path.write_text("\n".join(sfuzz_shards[worker_id]) + "\n", encoding="utf-8")
        workload_path.write_text("\n".join(workload_shards[worker_id]) + "\n", encoding="utf-8")
        sfuzz_paths.append(sfuzz_path)
        workload_paths.append(workload_path)
    return sfuzz_paths, workload_paths


def command_to_text(command: list[str]) -> str:
    return " ".join(shlex.quote(item) for item in command)


def run_py() -> str:
    return sys.executable or "python3"


def build_common_args(args: argparse.Namespace, work_dir: Path, output_csv: Path, output_json: Path, coverage: str) -> list[str]:
    common = [
        "--config",
        str(args.config),
        "--linknan-root",
        str(args.linknan_root),
        "--work-dir",
        str(work_dir),
        "--no-cycle-limit",
        "--timeout-sec",
        str(args.timeout_sec),
        "--firrtl-cov",
        coverage,
        "--output-csv",
        str(output_csv),
        "--output-json",
        str(output_json),
    ]
    if args.build_mode == "auto":
        pass
    elif args.build_mode == "build":
        common.append("--build")
    elif args.build_mode == "rebuild":
        common.extend(["--build", "--rebuild-comp"])
    else:
        common.append("--skip-build")
    if args.build_chisel:
        common.append("--build-chisel")
    if args.build_timeout_sec > 0:
        common.extend(["--build-timeout-sec", str(args.build_timeout_sec)])
    if args.simv_args:
        common.extend(["--simv-args", args.simv_args])
    return common


def method_build_dir(args: argparse.Namespace, method: str, paths: CampaignPaths, worker_id: int | None = None) -> Path | None:
    if not getattr(args, "isolated_sim_dirs", True):
        return None
    if worker_id is not None:
        return paths.results / method / "workers" / f"worker-{worker_id:03d}" / "linknan-build"
    return paths.results / method / "linknan-build"


def method_sim_dir(args: argparse.Namespace, method: str, paths: CampaignPaths, worker_id: int | None = None) -> Path | None:
    if not getattr(args, "isolated_sim_dirs", True):
        return None
    if worker_id is not None:
        return paths.results / method / "workers" / f"worker-{worker_id:03d}" / "linknan-sim"
    return paths.results / method / "linknan-sim"


def copy_or_link_file(source: Path, dest: Path) -> None:
    try:
        os.link(source, dest)
    except OSError:
        shutil.copy2(source, dest)


def command_option_path(command: list[str], option: str) -> Path | None:
    try:
        index = command.index(option)
    except ValueError:
        return None
    if index + 1 >= len(command):
        return None
    return Path(command[index + 1]).expanduser().resolve()


def copy_prepared_build_dir(source: Path, dest: Path) -> None:
    if source == dest:
        return
    if dest.exists():
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, dest, symlinks=True, copy_function=copy_or_link_file)


def generate_isolated_firrtl_coverage(
    *,
    args: argparse.Namespace,
    paths: CampaignPaths,
    method: str,
    coverage: str,
    build_dir: Path,
    source_rtl: Path,
    source_generated: Path,
    generator: Path,
) -> None:
    build_dir.mkdir(parents=True, exist_ok=True)
    rtl_dir = build_dir / "rtl"
    if rtl_dir.is_symlink():
        rtl_dir.unlink()
    if not rtl_dir.exists():
        shutil.copytree(source_rtl, rtl_dir, symlinks=True, copy_function=copy_or_link_file)
    elif not rtl_dir.is_dir():
        raise FileExistsError(f"isolated build RTL path exists but is not a directory: {rtl_dir}")
    bind_path = rtl_dir / "verification" / "cover" / "sfuzz_firrtl_cover_bind.sv"
    if bind_path.exists() or bind_path.is_symlink():
        bind_path.unlink()
    generated_dir = build_dir / "generated-src"
    generated_dir.mkdir(parents=True, exist_ok=True)
    if source_generated.is_dir():
        for item in source_generated.iterdir():
            dest = generated_dir / item.name
            if dest.exists():
                continue
            if item.is_dir():
                shutil.copytree(item, dest, symlinks=True, copy_function=copy_or_link_file)
            else:
                copy_or_link_file(item, dest)
    log_path = paths.logs / f"prepare-{method}-firrtl-coverage.log"
    command = [
        run_py(),
        str(generator),
        str(rtl_dir),
        "--generated-src-dir",
        str(generated_dir),
        "--groups",
        coverage,
    ]
    with log_path.open("w", encoding="utf-8") as log_file:
        result = subprocess.run(
            command,
            cwd=args.linknan_root.expanduser().resolve(),
            text=True,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            check=False,
        )
    if result.returncode != 0:
        raise RuntimeError(f"failed to prepare {method} FIRRTL coverage artifacts; see {log_path}")


def prepare_isolated_build_dirs(args: argparse.Namespace, paths: CampaignPaths, commands: list[dict[str, Any]]) -> None:
    if not getattr(args, "isolated_sim_dirs", True):
        return
    if getattr(args, "build_chisel", False):
        return
    source_build = args.linknan_root.expanduser().resolve() / "build"
    source_rtl = source_build / "rtl"
    source_generated = source_build / "generated-src"
    if not source_rtl.is_dir():
        raise FileNotFoundError(f"missing source LinkNan RTL directory for isolated campaign builds: {source_rtl}")
    generator = args.linknan_root.expanduser().resolve() / "scripts" / "linknan" / "sfuzz_firrtl_cov.py"
    if not generator.is_file():
        raise FileNotFoundError(f"missing LinkNan FIRRTL coverage generator: {generator}")
    prepared: set[Path] = set()
    template_by_coverage: dict[str, Path] = {}
    for item in commands:
        method = str(item["method"])
        coverage = str(item["coverage_name"])
        build_dir = command_option_path(list(item["command"]), "--build-dir")
        if build_dir is None or build_dir in prepared:
            continue
        prepared.add(build_dir)
        template = template_by_coverage.get(coverage)
        if template is not None:
            copy_prepared_build_dir(template, build_dir)
            continue
        generate_isolated_firrtl_coverage(
            args=args,
            paths=paths,
            method=method,
            coverage=coverage,
            build_dir=build_dir,
            source_rtl=source_rtl,
            source_generated=source_generated,
            generator=generator,
        )
        template_by_coverage[coverage] = build_dir


def selected_methods(args: argparse.Namespace) -> set[str]:
    values = getattr(args, "method", None) or []
    return {str(value).lower() for value in values}


def filter_commands(commands: list[dict[str, Any]], args: argparse.Namespace) -> list[dict[str, Any]]:
    selected = selected_methods(args)
    if not selected:
        return commands
    filtered = [item for item in commands if str(item.get("method", "")).lower() in selected]
    missing = sorted(selected - {str(item.get("method", "")).lower() for item in filtered})
    if missing:
        raise ValueError(f"unknown campaign method(s): {', '.join(missing)}")
    return filtered


def per_worker_budget(total_budget: int, worker_count: int) -> int:
    workers = max(1, worker_count)
    return max(1, (max(0, total_budget) + workers - 1) // workers)


def worker_paths(paths: CampaignPaths, method: str, worker_id: int, worker_count: int) -> tuple[Path, Path, Path]:
    if worker_count <= 1:
        return paths.results / method / "work", paths.results / method / "results.csv", paths.results / method / "results.json"
    root = paths.results / method / "workers" / f"worker-{worker_id:03d}"
    return root / "work", root / "results.csv", root / "results.json"


def campaign_commands(
    args: argparse.Namespace,
    paths: CampaignPaths,
    sfuzz_lists: list[Path] | Path,
    workload_lists: list[Path] | Path,
) -> list[dict[str, Any]]:
    run_script = SFUZZ_HOME / "scripts" / "linknan" / "run.py"
    direct_metadata = args.direct_metadata.expanduser().resolve()
    surge_manifest = args.surge_target_manifest.expanduser().resolve()
    commands: list[dict[str, Any]] = []
    sfuzz_shards = sfuzz_lists if isinstance(sfuzz_lists, list) else [sfuzz_lists]
    workload_shards = workload_lists if isinstance(workload_lists, list) else [workload_lists]
    worker_count = max(1, int(getattr(args, "workers_per_fuzzer", 1) or 1))
    worker_count = min(worker_count, max(len(sfuzz_shards), len(workload_shards)))
    worker_budget = per_worker_budget(args.exec_budget, worker_count)
    linknan_env = {"NUM_CORES": str(args.sfuzz_num_cores)}

    def add(
        method: str,
        coverage: str,
        formal_guard: str,
        tail: list[str],
        env: dict[str, str] | None = None,
        worker_id: int | None = None,
        seed_list: Path | None = None,
    ) -> None:
        work_dir, output_csv, output_json = worker_paths(paths, method, worker_id or 0, worker_count)
        command = [run_py(), str(run_script), method]
        command.extend(build_common_args(args, work_dir, output_csv, output_json, coverage))
        build_dir = method_build_dir(args, method, paths, worker_id if worker_count > 1 else None)
        sim_dir = method_sim_dir(args, method, paths, worker_id if worker_count > 1 else None)
        if build_dir is not None:
            command.extend(["--build-dir", str(build_dir)])
        if sim_dir is not None:
            command.extend(["--sim-dir", str(sim_dir)])
        command.extend(tail)
        commands.append(
            {
                "method": method,
                "worker_id": "" if worker_id is None else worker_id,
                "command": command,
                "env": env or {},
                "work_dir": work_dir,
                "output_csv": output_csv,
                "output_json": output_json,
                "coverage_name": coverage,
                "formal_guard": formal_guard,
                "seed_list": seed_list or "",
            }
        )

    for worker_id in range(worker_count):
        sfuzz_seed_list = sfuzz_shards[worker_id]
        workload_seed_list = workload_shards[worker_id]
        rng_seed = args.rng_seed + worker_id
        add(
            "sfuzz",
            "SFUZZ.native",
            "SFUZZ.native; semantic scheduler; short_run filtered by target_min_wall_time_sec",
            [
                "--seed-list",
                str(sfuzz_seed_list),
                "--campaign-runs",
                str(worker_budget),
                "--rng-seed",
                str(rng_seed),
                "--scheduler-policy",
                args.sfuzz_scheduler,
                "--target-min-wall-time-sec",
                str(args.target_min_wall_time_sec),
                "--enable-core1-handoff",
            ],
            linknan_env,
            worker_id,
            sfuzz_seed_list,
        )
        add(
            "rfuzz",
            "RFuzz.mux-toggle",
            "--require-formal-feedback; LinkNan workload scope; VCS native mux-toggle",
            [
                "--seed-list",
                str(workload_seed_list),
                "--rfuzz-rounds",
                str(worker_budget),
                "--formal-campaign-total-execs",
                str(args.exec_budget),
                "--rfuzz-random-seed",
                str(rng_seed),
                "--rfuzz-toggle-bitmap-source",
                "vcs-native-abi",
                "--require-formal-feedback",
            ],
            env=linknan_env,
            worker_id=worker_id,
            seed_list=workload_seed_list,
        )
        add(
            "directfuzz",
            "DirectFuzz.mux-toggle",
            "--require-paper-native; static metadata; dynamic per-instance VCS feedback",
            [
                "--seed-list",
                str(workload_seed_list),
                "--target-instance",
                args.direct_target_instance,
                "--metadata",
                str(direct_metadata),
                "--metadata-source",
                "static-analysis",
                "--coverage-backend",
                "native-file",
                "--native-coverage-source",
                "vcs-native-abi",
                "--max-execs",
                str(worker_budget),
                "--mutations",
                str(worker_budget),
                "--formal-campaign-total-execs",
                str(args.exec_budget),
                "--rng-seed",
                str(rng_seed),
                "--require-paper-native",
            ],
            env=linknan_env,
            worker_id=worker_id,
            seed_list=workload_seed_list,
        )
        add(
            "surgefuzz",
            "SurgeFuzz.trace",
            "--require-paper-native; single target; artifact Program mutation; no rotation",
            [
                "--input-mode",
                "artifact-program",
                "--max-execs",
                str(worker_budget),
                "--mutations",
                str(worker_budget),
                "--formal-campaign-total-execs",
                str(args.exec_budget),
                "--initial-seed-count",
                str(args.surge_initial_seed_count),
                "--rng-seed",
                str(rng_seed),
                "--target-manifest",
                str(surge_manifest),
                "--surge-target",
                args.surge_target,
                "--trace-source",
                "vcs-native-abi",
                "--require-paper-native",
            ],
            env=linknan_env,
            worker_id=worker_id,
        )
    return commands


def write_campaign_manifest(paths: CampaignPaths, testcases: list[Testcase], commands: list[dict[str, Any]], args: argparse.Namespace) -> Path:
    rows = [
        {
            "method": item["method"],
            "worker_id": item.get("worker_id", ""),
            "command": command_to_text(item["command"]),
            "env": ";".join(f"{key}={value}" for key, value in sorted(item.get("env", {}).items())),
            "work_dir": str(item["work_dir"]),
            "output_csv": str(item["output_csv"]),
            "output_json": str(item["output_json"]),
            "coverage_name": item["coverage_name"],
            "formal_guard": item["formal_guard"],
            "seed_list": str(item.get("seed_list", "")),
        }
        for item in commands
    ]
    csv_path = paths.manifests / "campaign_commands.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=CAMPAIGN_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    payload = {
        "campaign_root": str(paths.root),
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "testcase_count": len(testcases),
        "exec_budget": args.exec_budget,
        "timeout_sec": args.timeout_sec,
        "target_min_wall_time_sec": args.target_min_wall_time_sec,
        "rng_seed": args.rng_seed,
        "build_mode": args.build_mode,
        "sfuzz_num_cores": args.sfuzz_num_cores,
        "workers_per_fuzzer": args.workers_per_fuzzer,
        "parallel_jobs": args.parallel_jobs,
        "isolated_sim_dirs": args.isolated_sim_dirs,
        "commands": rows,
    }
    json_path = paths.manifests / "campaign_manifest.json"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    shell_path = paths.scripts / "run_all.sh"
    shell_lines = ["#!/usr/bin/env bash", "set -euo pipefail", ""]
    for item in commands:
        env_prefix = " ".join(f"{key}={shlex.quote(value)}" for key, value in sorted(item.get("env", {}).items()))
        shell_lines.append(f"{env_prefix + ' ' if env_prefix else ''}{command_to_text(item['command'])}")
    shell_path.write_text("\n".join(shell_lines) + "\n", encoding="utf-8")
    shell_path.chmod(0o755)
    return json_path


def validate_prepare(args: argparse.Namespace, testcases: list[Testcase]) -> None:
    if len(testcases) < args.min_testcases:
        raise ValueError(f"need at least {args.min_testcases} runnable testcases, found {len(testcases)}")
    if args.exec_budget < 1000:
        raise ValueError("formal four-fuzzer campaign requires --exec-budget >= 1000")
    if args.timeout_sec < 600:
        raise ValueError("formal four-fuzzer campaign requires --timeout-sec >= 600")
    if args.target_min_wall_time_sec < 60:
        raise ValueError("formal SFuzz campaign requires --target-min-wall-time-sec >= 60")
    require_file(args.direct_metadata.expanduser())
    require_file(args.surge_target_manifest.expanduser())


def run_commands(commands: list[dict[str, Any]], stop_on_failure: bool) -> int:
    overall = 0
    for item in commands:
        returncode = run_command_item(item)
        if returncode != 0:
            overall = returncode or 1
            if stop_on_failure:
                return overall
    return overall


def run_commands_parallel(commands: list[dict[str, Any]], jobs: int, stop_on_failure: bool) -> int:
    if jobs <= 1 or len(commands) <= 1:
        return run_commands(commands, stop_on_failure)
    overall = 0
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as executor:
        future_to_item = {executor.submit(run_command_item, item): item for item in commands}
        for future in as_completed(future_to_item):
            item = future_to_item[future]
            try:
                returncode = future.result()
            except BaseException:
                terminate_all_process_groups()
                for pending in future_to_item:
                    pending.cancel()
                raise
            if returncode != 0:
                overall = returncode or 1
                if stop_on_failure:
                    terminate_all_process_groups()
                    for pending in future_to_item:
                        pending.cancel()
                    return overall
    return overall


def run_command_item(item: dict[str, Any]) -> int:
    method = item["method"]
    command = item["command"]
    log_path = Path(item["work_dir"]).parent / "driver.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"[campaign] running {method}: {command_to_text(command)}", flush=True)
    env = os.environ.copy()
    env.update(item.get("env", {}))
    process: subprocess.Popen[str] | None = None
    try:
        with log_path.open("w", encoding="utf-8") as log_file:
            process = subprocess.Popen(
                command,
                cwd=SFUZZ_HOME,
                text=True,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                env=env,
                start_new_session=True,
            )
            register_process_group(process.pid)
            returncode = process.wait()
    except KeyboardInterrupt:
        if process is not None and process.poll() is None:
            terminate_process_group(process.pid)
        raise
    finally:
        if process is not None:
            unregister_process_group(process.pid)
    if returncode != 0:
        print(f"[campaign] {method} failed with code {returncode}, see {log_path}", flush=True)
    else:
        print(f"[campaign] {method} complete, log={log_path}", flush=True)
    return returncode


def terminate_process_group(pid: int) -> None:
    try:
        os.killpg(pid, 15)
    except ProcessLookupError:
        return


def register_process_group(pid: int) -> None:
    with ACTIVE_PROCESS_GROUPS_LOCK:
        ACTIVE_PROCESS_GROUPS.add(pid)


def unregister_process_group(pid: int) -> None:
    with ACTIVE_PROCESS_GROUPS_LOCK:
        ACTIVE_PROCESS_GROUPS.discard(pid)


def terminate_all_process_groups() -> None:
    with ACTIVE_PROCESS_GROUPS_LOCK:
        pids = list(ACTIVE_PROCESS_GROUPS)
    for pid in pids:
        terminate_process_group(pid)


def bool_text(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes"}


def numeric(value: Any) -> float | None:
    if value in {None, ""}:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def coverage_pair(row: dict[str, str]) -> tuple[float | None, float | None]:
    candidates = [
        ("accumulated_covered_bits", "common_coverage_total"),
        ("total_covered", "rfuzz_mux_total"),
        ("accumulated_covered_bits", "total"),
        ("global_ancestor_coverage", "coverage_total"),
    ]
    for covered_key, total_key in candidates:
        covered = numeric(row.get(covered_key))
        total = numeric(row.get(total_key))
        if covered is not None and total and total > 0:
            return covered, total
    value = numeric(row.get("common_coverage_value") or row.get("coverage_value"))
    if value is not None:
        return value, 100.0
    return None, None


def row_is_mutation(row: dict[str, str]) -> bool:
    markers = [
        row.get("mutation_index", ""),
        row.get("mutation", ""),
        row.get("mutation_kind", ""),
        row.get("round", ""),
    ]
    text = ";".join(str(item) for item in markers).lower()
    return bool(text) and not any(token in text for token in ["initial", "bootstrap", "seed", "initial-workload"])


def command_log_cycle_violation(row: dict[str, str]) -> bool:
    if bool_text(row.get("command_has_cycles_arg")) or bool_text(row.get("command_has_max_cycles_plusarg")):
        return True
    command_log = row.get("command_log_path") or ""
    if not command_log:
        return False
    path = Path(command_log)
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8", errors="replace")
    return "--cycles=" in text or "+max-cycles=5000" in text


def summarize_csv(method: str, csv_path: Path) -> dict[str, Any]:
    if not csv_path.is_file():
        return {
            "method": method,
            "result_csv": str(csv_path),
            "rows": 0,
            "mutation_rows": 0,
            "mutation_ratio": 0.0,
            "paper_faithful_rows": 0,
            "timed_out_rows": 0,
            "bug_rows": 0,
            "no_cycle_limit_rows": 0,
            "command_cycle_violations": 0,
            "final_covered": "",
            "final_total": "",
            "final_percent": "",
            "auc_exec_percent": "",
            "notes": "missing result CSV",
        }
    with csv_path.open(newline="", encoding="utf-8") as input_file:
        rows = list(csv.DictReader(input_file))
    coverage_percent: list[float] = []
    final_covered: float | None = None
    final_total: float | None = None
    for row in rows:
        covered, total = coverage_pair(row)
        if covered is None or not total:
            continue
        final_covered, final_total = covered, total
        coverage_percent.append(100.0 * covered / total)
    auc = sum(coverage_percent) / len(coverage_percent) if coverage_percent else ""
    final_percent = 100.0 * final_covered / final_total if final_covered is not None and final_total else ""
    mutation_rows = sum(1 for row in rows if row_is_mutation(row))
    return {
        "method": method,
        "result_csv": str(csv_path),
        "rows": len(rows),
        "mutation_rows": mutation_rows,
        "mutation_ratio": round(mutation_rows / len(rows), 6) if rows else 0.0,
        "paper_faithful_rows": sum(1 for row in rows if bool_text(row.get("paper_faithful"))),
        "timed_out_rows": sum(1 for row in rows if bool_text(row.get("timed_out"))),
        "bug_rows": sum(1 for row in rows if bool_text(row.get("bug_triggered")) or bool_text(row.get("design_bug"))),
        "no_cycle_limit_rows": sum(1 for row in rows if bool_text(row.get("no_max_cycle_limit"))),
        "command_cycle_violations": sum(1 for row in rows if command_log_cycle_violation(row)),
        "final_covered": int(final_covered) if final_covered is not None and float(final_covered).is_integer() else final_covered or "",
        "final_total": int(final_total) if final_total is not None and float(final_total).is_integer() else final_total or "",
        "final_percent": round(final_percent, 6) if final_percent != "" else "",
        "auc_exec_percent": round(auc, 6) if auc != "" else "",
        "notes": "",
    }


def aggregate(paths: CampaignPaths) -> Path:
    rows = []
    for method in ["sfuzz", "rfuzz", "directfuzz", "surgefuzz"]:
        worker_csvs = sorted((paths.results / method / "workers").glob("worker-*/results.csv"))
        if worker_csvs:
            merged_csv = paths.results / method / "results.csv"
            merge_worker_csvs(method, worker_csvs, merged_csv)
            rows.append(summarize_csv(method, merged_csv))
        else:
            rows.append(summarize_csv(method, paths.results / method / "results.csv"))
    output_json = paths.results / "aggregate_summary.json"
    output_csv = paths.results / "aggregate_summary.csv"
    write_table(rows, output_json, output_csv, SUMMARY_FIELDS, {"campaign_root": str(paths.root)})
    report = paths.reports / "t2_four_fuzzer_summary.md"
    lines = ["# T2 四工具长运行对比摘要", "", f"campaign: `{paths.root}`", "", "| method | rows | mutation rows | final coverage | AUC | notes |", "|---|---:|---:|---:|---:|---|"]
    for row in rows:
        final = ""
        if row["final_covered"] != "" and row["final_total"] != "":
            final = f"{row['final_covered']} / {row['final_total']} ({row['final_percent']}%)"
        lines.append(
            f"| {row['method']} | {row['rows']} | {row['mutation_rows']} | {final} | {row['auc_exec_percent']} | {row['notes']} |"
        )
    lines.append("")
    lines.append("正式结论需要逐项检查 command_cycle_violations=0、rows>=1000、mutation_ratio>=0.8。")
    report.write_text("\n".join(lines), encoding="utf-8")
    return output_csv


def merge_worker_csvs(method: str, worker_csvs: list[Path], output_csv: Path) -> None:
    fieldnames: list[str] = []
    rows: list[dict[str, Any]] = []
    for worker_csv in worker_csvs:
        with worker_csv.open(newline="", encoding="utf-8") as input_file:
            reader = csv.DictReader(input_file)
            if reader.fieldnames:
                for name in reader.fieldnames:
                    if name not in fieldnames:
                        fieldnames.append(name)
            worker_id = worker_csv.parent.name.replace("worker-", "")
            for row in reader:
                row = dict(row)
                row["worker_id"] = worker_id
                rows.append(row)
    if "worker_id" not in fieldnames:
        fieldnames.insert(0, "worker_id")
    output_json = output_csv.with_suffix(".json")
    write_table(rows, output_json, output_csv, fieldnames, {"method": method, "worker_csvs": [str(path) for path in worker_csvs]})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare, run, and aggregate a formal T2 four-fuzzer LinkNan campaign")
    parser.add_argument("--phase", choices=["prepare", "run", "aggregate", "all"], default="prepare")
    parser.add_argument("--campaign-root", type=Path, default=None)
    parser.add_argument("--manifest", type=Path, default=SFUZZ_HOME / "benchmarks" / "linknan" / "phase1_corpus_manifest.csv")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--linknan-root", type=Path, default=SFUZZ_HOME.parent / "LinkNan")
    parser.add_argument("--direct-metadata", type=Path, default=SFUZZ_HOME / "work" / "directfuzz-native" / "static_metadata_per_instance_full.csv")
    parser.add_argument("--surge-target-manifest", type=Path, default=SFUZZ_HOME / "config" / "surgefuzz_targets.toml")
    parser.add_argument("--direct-target-instance", default=DEFAULT_DIRECT_TARGET)
    parser.add_argument("--surge-target", default="memblock_load_miss")
    parser.add_argument("--limit", type=int, default=120, help="maximum testcase count selected from manifest")
    parser.add_argument("--min-testcases", type=int, default=100)
    parser.add_argument("--exec-budget", type=int, default=1000)
    parser.add_argument("--timeout-sec", type=int, default=600)
    parser.add_argument("--target-min-wall-time-sec", type=int, default=60)
    parser.add_argument("--rng-seed", type=int, default=20260605)
    parser.add_argument("--sfuzz-scheduler", choices=["weighted-innovation", "semantic-bandit"], default="semantic-bandit")
    parser.add_argument("--surge-initial-seed-count", type=int, default=1)
    parser.add_argument(
        "--build-mode",
        choices=["auto", "skip", "build", "rebuild"],
        default="auto",
        help="auto lets each runner rebuild simv when the requested coverage ABI does not match the current build",
    )
    parser.add_argument("--build-chisel", action="store_true")
    parser.add_argument("--build-timeout-sec", type=int, default=3600)
    parser.add_argument("--simv-args", default="")
    parser.add_argument("--sfuzz-num-cores", type=int, default=2)
    parser.add_argument("--workers-per-fuzzer", type=int, default=4)
    parser.add_argument("--parallel-jobs", type=int, default=16)
    parser.add_argument("--method", action="append", default=[], help="run only selected method; repeatable")
    parser.add_argument("--isolated-sim-dirs", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--keep-going", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    campaign_root = args.campaign_root or (SFUZZ_HOME / "campaigns" / f"t2-long-four-fuzzer-{now_slug()}")
    paths = CampaignPaths.create(campaign_root.expanduser().resolve())
    if args.phase in {"prepare", "all"}:
        testcases = load_testcases(args.manifest.expanduser(), args.limit)
        validate_prepare(args, testcases)
        sfuzz_list, workload_list, selected_manifest = write_seed_lists(paths, testcases)
        sfuzz_shards, workload_shards = write_seed_shards(paths, testcases, args.workers_per_fuzzer)
        commands = filter_commands(campaign_commands(args, paths, sfuzz_shards, workload_shards), args)
        prepare_isolated_build_dirs(args, paths, commands)
        manifest_json = write_campaign_manifest(paths, testcases, commands, args)
        print(f"prepared {len(testcases)} testcases")
        print(f"selected manifest: {selected_manifest}")
        print(f"campaign manifest: {manifest_json}")
    else:
        command_manifest = paths.manifests / "campaign_commands.csv"
        require_file(command_manifest)
        commands = []
        with command_manifest.open(newline="", encoding="utf-8") as input_file:
            for row in csv.DictReader(input_file):
                commands.append(
                    {
                        "method": row["method"],
                        "command": shlex.split(row["command"]),
                        "env": dict(
                            item.split("=", 1) for item in row.get("env", "").split(";") if item and "=" in item
                        ),
                        "work_dir": Path(row["work_dir"]),
                        "output_csv": Path(row["output_csv"]),
                        "output_json": Path(row["output_json"]),
                        "coverage_name": row["coverage_name"],
                        "formal_guard": row["formal_guard"],
                        "worker_id": row.get("worker_id", ""),
                        "seed_list": row.get("seed_list", ""),
                    }
                )
        commands = filter_commands(commands, args)
    if args.phase in {"run", "all"}:
        status = run_commands_parallel(commands, args.parallel_jobs, stop_on_failure=not args.keep_going)
        if status != 0:
            return status
    if args.phase in {"aggregate", "all"}:
        summary = aggregate(paths)
        print(f"aggregate summary: {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
