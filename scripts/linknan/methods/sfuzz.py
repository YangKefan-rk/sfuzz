from __future__ import annotations

import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..common import slugify, write_table
from ..config import VcsContext
from ..seeds import (
    SfuzSeed,
    collect_seed_paths,
    read_seed_metadata_name,
    read_sfuz_seed,
    seed_category,
    write_sfuz_seed,
)
from ..vcs import (
    CoverageResult,
    assertion_failure,
    build_simv_if_needed,
    classify_infrastructure_error,
    collect_vcs_coverage,
    common_coverage_backend,
    design_bug,
    design_bug_reasons,
    run_vcs_seed,
    scan_vcs_logs,
    wall_timeout,
)


SFUZZ_FIELDS = [
    "fuzzer",
    "campaign_exec",
    "seed_name",
    "seed_category",
    "seed_path",
    "input_kind",
    "input_size_bytes",
    "corpus_id",
    "parent_corpus_id",
    "mutation_index",
    "energy",
    "mutation_budget",
    "mutation_operators",
    "scheduler_policy",
    "scheduler_corpus_index",
    "scheduler_weight",
    "scheduler_total_weight",
    "retained",
    "retention_reason",
    "comparison_tier",
    "paper_faithful",
    "coverage_backend",
    "common_coverage_backend",
    "common_coverage_name",
    "common_coverage_value",
    "common_coverage_source",
    "common_coverage_status",
    "common_coverage_covered",
    "common_coverage_total",
    "new_coverage_bits",
    "accumulated_covered_bits",
    "required_native_abi",
    "wall_time_sec",
    "vcs_cycles",
    "vcs_cpu_time_sec",
    "vcs_sim_time_ps",
    "max_cycle_exceeded",
    "run_outcome",
    "t0_smoke_pass",
    "exit_code",
    "vcs_report_seen",
    "sfuz_expansion_seen",
    "good_trap_seen",
    "bug_triggered",
    "bug_reasons",
    "log_path",
    "assert_log_path",
    "command_log_path",
    "case_dir",
    "case_name",
    "timed_out",
    "wall_timeout",
    "design_bug",
    "assertion_failure",
    "design_bug_reasons",
    "infrastructure_error",
    "no_max_cycle_limit",
    "command_has_cycles_arg",
    "command_has_max_cycles_plusarg",
    "notes",
]

DEFAULT_CORE0_PROG = bytes.fromhex("73001000")
SFUZZ_SCHEDULER_POLICY = "coverage_weighted_energy"
SFUZZ_MUTATION_OPERATORS = (
    "bitflip_byte",
    "overwrite_byte",
    "bitflip_word",
    "delete_range",
    "insert_random_bytes",
)


@dataclass
class CorpusEntry:
    corpus_id: int
    path: Path
    seed_name: str
    category: str
    energy: int
    parent_corpus_id: int | str = ""
    mutation_index: int | str = ""
    mutation_budget: int | str = ""
    mutation_operators: str = ""
    scheduler_policy: str = ""
    scheduler_corpus_index: int | str = ""
    scheduler_weight: int | str = ""
    scheduler_total_weight: int | str = ""


@dataclass(frozen=True)
class MutationSummary:
    budget: int
    operators: tuple[str, ...]

    @property
    def operator_trace(self) -> str:
        return ";".join(self.operators)


@dataclass(frozen=True)
class SchedulerSelection:
    entry: CorpusEntry
    corpus_index: int
    weight: int
    total_weight: int
    policy: str = SFUZZ_SCHEDULER_POLICY


def run_outcome(result: Any, info: Any, infrastructure_error: str) -> str:
    if result.timed_out:
        return "timeout"
    if infrastructure_error:
        return "infrastructure_error"
    if info.bug_triggered:
        return "bug_triggered"
    if info.good_trap_seen:
        return "good_trap"
    if info.max_cycle_exceeded:
        return "max_cycle_reached"
    if info.finish_seen:
        return "finished"
    return "unknown"


def read_bitmap(coverage: CoverageResult) -> bytes | None:
    if not coverage.bitmap_path:
        return None
    path = Path(coverage.bitmap_path)
    if not path.is_file():
        return None
    return path.read_bytes()


def coverage_delta(bitmap: bytes | None, accumulated: bytearray) -> int:
    if bitmap is None:
        return 0
    if not accumulated:
        accumulated.extend(b"\x00" * len(bitmap))
    if len(bitmap) != len(accumulated):
        raise ValueError(f"coverage bitmap size changed: {len(bitmap)} != {len(accumulated)}")
    new_bits = 0
    for idx, value in enumerate(bitmap):
        delta = value & (~accumulated[idx] & 0xFF)
        if delta:
            new_bits += delta.bit_count()
            accumulated[idx] |= value
    return new_bits


def accumulated_covered(accumulated: bytearray) -> int:
    return sum(value.bit_count() for value in accumulated)


def bounded_energy(new_bits: int, min_energy: int, max_energy: int) -> int:
    lo = max(1, min_energy)
    hi = max(lo, max_energy)
    if new_bits <= 0:
        return lo
    return min(hi, lo + new_bits.bit_length())


def normalized_mutation_budget(budget: int) -> int:
    return max(1, int(budget))


def scheduler_weight(entry: CorpusEntry) -> int:
    try:
        return max(1, int(entry.energy))
    except (TypeError, ValueError):
        return 1


def select_weighted_parent(corpus: list[CorpusEntry], rng: random.Random) -> SchedulerSelection:
    if not corpus:
        raise ValueError("SFuzz scheduler requires a non-empty corpus")
    weights = [scheduler_weight(entry) for entry in corpus]
    total = sum(weights)
    ticket = rng.randrange(total)
    cursor = 0
    for idx, weight in enumerate(weights):
        cursor += weight
        if ticket < cursor:
            return SchedulerSelection(corpus[idx], idx, weight, total)
    last_idx = len(corpus) - 1
    return SchedulerSelection(corpus[last_idx], last_idx, weights[last_idx], total)


def ensure_core0_program(core0: bytearray) -> None:
    if not core0:
        core0.extend(DEFAULT_CORE0_PROG)


def available_mutation_operators(core0: bytearray) -> tuple[str, ...]:
    operators = ["bitflip_byte", "overwrite_byte"]
    if len(core0) >= 4:
        operators.append("bitflip_word")
    if len(core0) > 4:
        operators.append("delete_range")
    operators.append("insert_random_bytes")
    return tuple(operators)


def mutation_operator_selection_pool(core0: bytearray) -> tuple[str, ...]:
    return (
        "bitflip_byte",
        "overwrite_byte",
        "bitflip_word" if len(core0) >= 4 else "insert_random_bytes",
        "delete_range" if len(core0) > 4 else "insert_random_bytes",
        "insert_random_bytes",
    )


def choose_mutation_operator(core0: bytearray, rng: random.Random) -> str:
    ensure_core0_program(core0)
    operators = mutation_operator_selection_pool(core0)
    return operators[rng.randrange(len(operators))]


def apply_sfuz_mutation_operator(core0: bytearray, operator: str, rng: random.Random) -> None:
    if operator not in SFUZZ_MUTATION_OPERATORS:
        raise ValueError(f"unsupported SFuzz mutation operator: {operator}")
    ensure_core0_program(core0)
    if operator == "bitflip_byte":
        idx = rng.randrange(len(core0))
        core0[idx] ^= 1 << rng.randrange(8)
    elif operator == "overwrite_byte":
        idx = rng.randrange(len(core0))
        core0[idx] = rng.randrange(256)
    elif operator == "bitflip_word":
        if len(core0) < 4:
            raise ValueError("bitflip_word requires at least 4 bytes")
        word_count = len(core0) // 4
        word_idx = rng.randrange(word_count)
        start = word_idx * 4
        word = int.from_bytes(core0[start : start + 4], "little")
        word ^= 1 << rng.randrange(32)
        core0[start : start + 4] = word.to_bytes(4, "little")
    elif operator == "delete_range":
        if len(core0) <= 4:
            raise ValueError("delete_range requires more than 4 bytes")
        start = rng.randrange(len(core0))
        width = rng.randrange(1, min(8, len(core0) - start) + 1)
        del core0[start : min(len(core0), start + width)]
    elif operator == "insert_random_bytes":
        idx = rng.randrange(len(core0) + 1)
        core0[idx:idx] = rng.randbytes(rng.randrange(1, 9))


def mutate_core0_program(core0: bytearray, rng: random.Random, budget: int) -> MutationSummary:
    mutation_budget = normalized_mutation_budget(budget)
    operators: list[str] = []
    ensure_core0_program(core0)
    for _ in range(mutation_budget):
        operator = choose_mutation_operator(core0, rng)
        apply_sfuz_mutation_operator(core0, operator, rng)
        operators.append(operator)
    return MutationSummary(mutation_budget, tuple(operators))


def mutate_sfuz(parent: Path, output: Path, rng: random.Random, budget: int) -> MutationSummary:
    seed = read_sfuz_seed(parent)
    core0 = bytearray(seed.core0_prog)
    summary = mutate_core0_program(core0, rng, budget)
    mutated = SfuzSeed(
        core0_prog=bytes(core0),
        core1_prog=seed.core1_prog,
        shared_mem_init=seed.shared_mem_init,
        interrupt_plan_raw=seed.interrupt_plan_raw,
        name=f"{seed.name or parent.stem}.mut",
        description=f"mutated from {parent}",
        tags=[*seed.tags, "sfuzz-online-mutated"],
    )
    write_sfuz_seed(output, mutated)
    return summary


def command_cycle_markers(command_log: str) -> tuple[bool, bool]:
    path = Path(command_log)
    if not path.is_file():
        return False, False
    text = path.read_text(encoding="utf-8", errors="replace")
    return "--cycles=" in text, "+max-cycles=" in text


def run_one(args: Any, ctx: VcsContext, runs_dir: Path, logs_dir: Path, seed: Path, case_name: str) -> dict[str, Any]:
    extra_env = {}
    firrtl_cov = getattr(args, "firrtl_cov", None)
    if firrtl_cov:
        extra_env["SFUZZ_FIRRTL_COV"] = str(firrtl_cov)
    result, case_dir, run_log, assert_log = run_vcs_seed(
        seed=seed,
        case_name=case_name,
        runs_dir=runs_dir,
        logs_dir=logs_dir,
        ctx=ctx,
        timeout_sec=args.timeout_sec,
        cov=args.cov,
        simv_args=args.simv_args,
        extra_env=extra_env or None,
    )
    info = scan_vcs_logs(run_log, assert_log, ctx.cycles)

    infrastructure_error = classify_infrastructure_error(result, info, run_log)

    coverage = collect_vcs_coverage(args, case_dir, ctx.sim_dir)
    has_cycles_arg, has_max_cycles_plusarg = command_cycle_markers(result.command_log_path)
    coverage_backend = common_coverage_backend(coverage)
    comparison_tier = "T1_common_backend_online" if coverage_backend == "sfuzz_firrtl" else "T0_smoke"
    t0_smoke_pass = (
        result.returncode == 0
        and info.sfuz_expansion_seen
        and info.vcs_report_seen
        and not info.bug_triggered
        and not infrastructure_error
    )
    return {
        "result": result,
        "info": info,
        "coverage": coverage,
        "coverage_backend": coverage_backend,
        "comparison_tier": comparison_tier,
        "t0_smoke_pass": t0_smoke_pass,
        "infrastructure_error": infrastructure_error,
        "run_outcome": run_outcome(result, info, infrastructure_error),
        "run_log": run_log,
        "assert_log": assert_log,
        "case_dir": case_dir,
        "case_name": case_name,
        "command_has_cycles_arg": has_cycles_arg,
        "command_has_max_cycles_plusarg": has_max_cycles_plusarg,
    }


def row_from_run(
    *,
    args: Any,
    ctx: VcsContext,
    campaign_exec: int,
    entry: CorpusEntry,
    run: dict[str, Any],
    new_bits: int,
    accumulated: bytearray,
    retained: bool,
    retention_reason: str,
    notes: str,
) -> dict[str, Any]:
    coverage = run["coverage"]
    seed = entry.path
    return {
        "fuzzer": "sfuzz",
        "campaign_exec": campaign_exec,
        "seed_name": entry.seed_name,
        "seed_category": entry.category,
        "seed_path": str(seed),
        "input_kind": "sfuz",
        "input_size_bytes": seed.stat().st_size,
        "corpus_id": entry.corpus_id,
        "parent_corpus_id": entry.parent_corpus_id,
        "mutation_index": entry.mutation_index,
        "energy": entry.energy,
        "mutation_budget": entry.mutation_budget,
        "mutation_operators": entry.mutation_operators,
        "scheduler_policy": entry.scheduler_policy,
        "scheduler_corpus_index": entry.scheduler_corpus_index,
        "scheduler_weight": entry.scheduler_weight,
        "scheduler_total_weight": entry.scheduler_total_weight,
        "retained": retained,
        "retention_reason": retention_reason,
        "comparison_tier": run["comparison_tier"],
        "paper_faithful": run["coverage_backend"] == "sfuzz_firrtl",
        "coverage_backend": run["coverage_backend"],
        "common_coverage_backend": run["coverage_backend"],
        "common_coverage_name": coverage.coverage_name,
        "common_coverage_value": coverage.coverage_value,
        "common_coverage_source": coverage.coverage_source,
        "common_coverage_status": coverage.coverage_status,
        "common_coverage_covered": coverage.covered if coverage.covered is not None else "",
        "common_coverage_total": coverage.total if coverage.total is not None else "",
        "new_coverage_bits": new_bits,
        "accumulated_covered_bits": accumulated_covered(accumulated),
        "required_native_abi": "" if run["coverage_backend"] == "sfuzz_firrtl" else "sfuzz_linknan_native_bitmap",
        "wall_time_sec": round(run["result"].wall_time_sec, 3),
        "vcs_cycles": run["info"].cycles if run["info"].cycles is not None else "",
        "vcs_cpu_time_sec": run["info"].vcs_cpu_time_sec,
        "vcs_sim_time_ps": run["info"].vcs_sim_time_ps,
        "max_cycle_exceeded": run["info"].max_cycle_exceeded,
        "run_outcome": run["run_outcome"],
        "t0_smoke_pass": run["t0_smoke_pass"],
        "exit_code": run["result"].returncode,
        "vcs_report_seen": run["info"].vcs_report_seen,
        "sfuz_expansion_seen": run["info"].sfuz_expansion_seen,
        "good_trap_seen": run["info"].good_trap_seen,
        "bug_triggered": run["info"].bug_triggered,
        "bug_reasons": run["info"].bug_reasons,
        "log_path": str(run["run_log"]),
        "assert_log_path": str(run["assert_log"]),
        "command_log_path": run["result"].command_log_path,
        "case_dir": str(run["case_dir"]),
        "case_name": run["case_name"],
        "timed_out": run["result"].timed_out,
        "wall_timeout": wall_timeout(run["result"]),
        "design_bug": design_bug(run["info"]),
        "assertion_failure": assertion_failure(run["info"]),
        "design_bug_reasons": design_bug_reasons(run["info"]),
        "infrastructure_error": run["infrastructure_error"],
        "no_max_cycle_limit": not run["command_has_cycles_arg"] and not run["command_has_max_cycles_plusarg"],
        "command_has_cycles_arg": run["command_has_cycles_arg"],
        "command_has_max_cycles_plusarg": run["command_has_max_cycles_plusarg"],
        "notes": notes,
    }


def initial_corpus(args: Any, work_dir: Path) -> list[CorpusEntry]:
    seeds = collect_seed_paths(args.seed, args.seed_list, args.seed_dir, work_dir, args.limit, True, "sfuzz-smoke")
    entries: list[CorpusEntry] = []
    for idx, seed in enumerate(seeds):
        seed_name = read_seed_metadata_name(seed)
        entries.append(
            CorpusEntry(
                corpus_id=idx,
                path=seed,
                seed_name=seed_name,
                category=seed_category(seed, seed_name),
                energy=max(1, getattr(args, "min_energy", 1)),
            )
        )
    return entries


def run_sfuzz(args: Any, ctx: VcsContext) -> int:
    if not getattr(args, "batch_replay", False):
        if not getattr(args, "no_cycle_limit", False) or ctx.cycles is not None:
            raise SystemExit("SFuzz online mode requires --no-cycle-limit; use --timeout-sec as the external stop condition")
        if not getattr(args, "timeout_sec", 0):
            raise SystemExit("SFuzz online mode requires --timeout-sec so unbounded VCS runs have an external guard")
        if not getattr(args, "firrtl_cov", None):
            args.firrtl_cov = "FIRRTL.common"

    work_dir = args.work_dir.expanduser().resolve()
    runs_dir = work_dir / "runs"
    logs_dir = work_dir / "logs"
    generated_dir = work_dir / "generated"
    runs_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    generated_dir.mkdir(parents=True, exist_ok=True)

    build_simv_if_needed(args, ctx, work_dir)
    corpus = initial_corpus(args, work_dir)
    rows: list[dict[str, Any]] = []
    accumulated = bytearray()
    rng = random.Random(getattr(args, "rng_seed", 1))
    campaign_runs = len(corpus) if getattr(args, "batch_replay", False) else max(1, getattr(args, "campaign_runs", 8))
    next_corpus_id = len(corpus)
    mutation_counter = 0

    for exec_idx in range(1, campaign_runs + 1):
        if getattr(args, "batch_replay", False):
            entry = corpus[exec_idx - 1]
            entry.scheduler_policy = "batch_replay"
        elif exec_idx <= len(corpus):
            entry = corpus[exec_idx - 1]
            entry.scheduler_policy = "initial_corpus"
        else:
            scheduled = select_weighted_parent(corpus, rng)
            parent = scheduled.entry
            mutation_counter += 1
            mutated_path = generated_dir / f"sfuzz-mut-{mutation_counter:04d}.sfuz"
            mutation = mutate_sfuz(parent.path, mutated_path, rng, parent.energy)
            seed_name = read_seed_metadata_name(mutated_path)
            entry = CorpusEntry(
                corpus_id=next_corpus_id,
                path=mutated_path,
                seed_name=seed_name,
                category=seed_category(mutated_path, seed_name),
                energy=parent.energy,
                parent_corpus_id=parent.corpus_id,
                mutation_index=mutation_counter,
                mutation_budget=mutation.budget,
                mutation_operators=mutation.operator_trace,
                scheduler_policy=scheduled.policy,
                scheduler_corpus_index=scheduled.corpus_index,
                scheduler_weight=scheduled.weight,
                scheduler_total_weight=scheduled.total_weight,
            )
            next_corpus_id += 1

        case_name = f"{slugify(args.case_prefix)}-{exec_idx:04d}-{slugify(entry.seed_name)}"
        run = run_one(args, ctx, runs_dir, logs_dir, entry.path, case_name)
        bitmap = read_bitmap(run["coverage"])
        new_bits = coverage_delta(bitmap, accumulated)
        retained = new_bits > 0 or run["run_outcome"] == "bug_triggered"
        retention_reason = "new_coverage" if new_bits > 0 else run["run_outcome"] if retained else "not_interesting"
        if retained:
            entry.energy = bounded_energy(new_bits, args.min_energy, args.max_energy)
            if entry not in corpus:
                corpus.append(entry)
        notes = (
            "online SFuzz loop; coverage delta drives corpus retention, mutation energy, and weighted parent selection; "
            "use --batch-replay only for legacy fixed manifest replay"
        )
        rows.append(
            row_from_run(
                args=args,
                ctx=ctx,
                campaign_exec=exec_idx,
                entry=entry,
                run=run,
                new_bits=new_bits,
                accumulated=accumulated,
                retained=retained,
                retention_reason=retention_reason,
                notes=notes,
            )
        )
        print(
            f"[{exec_idx}/{campaign_runs}] sfuzz outcome={run['run_outcome']} "
            f"new={new_bits} acc={accumulated_covered(accumulated)} log={run['run_log']}",
            flush=True,
        )

    write_table(
        rows,
        args.output_json or work_dir / "results.json",
        args.output_csv or work_dir / "results.csv",
        SFUZZ_FIELDS,
        {"fuzzer": "sfuzz", "mode": "batch_replay" if getattr(args, "batch_replay", False) else "online"},
    )
    return 0
