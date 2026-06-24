from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..common import slugify, write_table
from ..config import VcsContext
from ..seeds import (
    SfuzSeed,
    collect_seed_paths,
    infer_seed_micro_ir,
    read_seed_metadata_name,
    read_sfuz_seed,
    seed_category,
    write_sfuz_seed,
)
from ..sfuzz_scenarios import (
    choose_semantic_operator,
    family_default_operator,
    scenario_from_operator,
    write_scenario_artifacts,
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
    "mutation_sections",
    "seed_ir_targets",
    "seed_event_plan",
    "coverage_group_focus",
    "coverage_group_deficit",
    "coverage_group_new_bits",
    "coverage_group_accumulated_bits",
    "hard_target_first_hits",
    "scheduler_policy",
    "scheduler_family",
    "scheduler_bucket",
    "innovation_enabled",
    "scheduler_corpus_index",
    "scheduler_weight",
    "scheduler_total_weight",
    "semantic_operator_credit",
    "semantic_operator_stall",
    "scenario_family_credit",
    "scenario_family_stall",
    "retained",
    "retention_reason",
    "comparison_tier",
    "paper_faithful",
    "coverage_backend",
    "coverage_bitmap_semantics",
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
    "target_min_wall_time_sec",
    "short_run",
    "vcs_cycles",
    "vcs_cpu_time_sec",
    "vcs_sim_time_ps",
    "max_cycle_exceeded",
    "run_outcome",
    "t0_smoke_pass",
    "exit_code",
    "vcs_report_seen",
    "sfuz_expansion_seen",
    "sfuzz_core0_staged",
    "sfuzz_core1_staged",
    "sfuzz_core1_entry",
    "sfuzz_core1_payload_size",
    "core1_executed",
    "core1_handoff_reason",
    "requires_core1_handoff",
    "formal_multicore_result",
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
BASELINE_SCHEDULER_POLICY = "baseline_fifo"
WEIGHTED_SCHEDULER_POLICY = "weighted_innovation"
SEMANTIC_BANDIT_SCHEDULER_POLICY = "semantic_bandit"
SFUZZ_SCHEDULER_POLICY = WEIGHTED_SCHEDULER_POLICY
SFUZZ_COVERAGE_BITMAP_SEMANTICS = "byte_per_point_nonzero_hit"
SFUZZ_NATIVE_COVERAGE_NAME = "SFUZZ.native"
SFUZZ_NATIVE_GROUP = "sfuzz_native"
SFUZZ_HARD_TARGET_GROUPS = (
    "sfuzz_atomic",
    "sfuzz_fence",
    "sfuzz_lsq",
    "sfuzz_coherence",
    "sfuzz_mmu",
    "sfuzz_resource",
)
SFUZZ_MUTATION_OPERATORS = (
    "bitflip_byte",
    "overwrite_byte",
    "bitflip_word",
    "delete_range",
    "insert_random_bytes",
)
SFUZZ_SHARED_MUTATION_OPERATORS = (
    "shared_insert_segment",
    "shared_delete_segment",
    "shared_mutate_base",
    "shared_bitflip_byte",
    "shared_overwrite_byte",
    "shared_insert_random_bytes",
    "shared_delete_range",
)
SFUZZ_INTERRUPT_MUTATION_OPERATORS = (
    "interrupt_insert_event",
    "interrupt_delete_event",
    "interrupt_bitflip_byte",
    "interrupt_overwrite_byte",
)
SFUZZ_MUTATION_SECTIONS = ("core0", "core1", "shared", "interrupt")
MICRO_GROUP_SECTION_HINTS = {
    "sfuzz_frontend": ("core0", "core1", "interrupt"),
    "sfuzz_branch": ("core0", "core1"),
    "sfuzz_mmu": ("shared", "core0", "core1", "interrupt"),
    "sfuzz_rob": ("core0", "core1"),
    "sfuzz_exception": ("interrupt", "core0", "core1"),
    "sfuzz_lsq": ("shared", "core0", "core1"),
    "sfuzz_dcache": ("shared", "core0", "core1"),
    "sfuzz_atomic": ("shared", "core0", "core1"),
    "sfuzz_fence": ("shared", "core0", "core1"),
    "sfuzz_coherence": ("shared", "core0", "core1"),
    "sfuzz_resource": ("shared", "core0", "core1", "interrupt"),
    "sfuzz_native": ("shared", "core0", "core1", "interrupt"),
    "ready_valid": ("core0", "core1"),
    "mux": ("core0", "core1"),
    "toggle": ("core0", "core1", "shared"),
    "control_event": ("core0", "core1", "interrupt"),
    "queue_event": ("shared", "core0", "core1"),
    "memory_event": ("shared", "core0", "core1"),
    "branch_event": ("core0", "core1"),
    "exception_event": ("interrupt", "core0", "core1"),
    "resource_event": ("shared", "core0", "core1", "interrupt"),
    "surgefuzz_trace": ("shared", "core0", "core1"),
}
MICRO_GROUP_PRIORITY = {
    "sfuzz_atomic": 8,
    "sfuzz_fence": 8,
    "sfuzz_lsq": 7,
    "sfuzz_coherence": 7,
    "sfuzz_mmu": 6,
    "sfuzz_dcache": 6,
    "sfuzz_exception": 6,
    "sfuzz_branch": 5,
    "sfuzz_resource": 5,
    "sfuzz_frontend": 4,
    "sfuzz_rob": 4,
    "sfuzz_native": 4,
    "memory_event": 4,
    "branch_event": 4,
    "exception_event": 4,
    "resource_event": 3,
    "queue_event": 3,
    "control_event": 2,
    "ready_valid": 1,
    "mux": 1,
    "toggle": 1,
    "surgefuzz_trace": 2,
}


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
    mutation_sections: str = ""
    seed_ir_targets: str = ""
    seed_event_plan: str = ""
    coverage_group_focus: str = ""
    coverage_group_deficit: int | str = ""
    coverage_group_new_bits: str = ""
    coverage_group_accumulated_bits: str = ""
    hard_target_first_hits: str = ""
    scheduler_policy: str = ""
    scheduler_family: str = ""
    scheduler_bucket: str = ""
    innovation_enabled: bool | str = ""
    scheduler_corpus_index: int | str = ""
    scheduler_weight: int | str = ""
    scheduler_total_weight: int | str = ""
    semantic_operator_credit: int | str = ""
    semantic_operator_stall: int | str = ""
    scenario_family_credit: int | str = ""
    scenario_family_stall: int | str = ""
    requires_core1_handoff: bool = False
    core1_handoff_enabled: bool = False
    target_min_wall_time_sec: int = 0
    total_new_coverage_bits: int = 0
    no_new_coverage_streak: int = 0
    execution_count: int = 0


@dataclass(frozen=True)
class MutationSummary:
    budget: int
    operators: tuple[str, ...]
    sections: tuple[str, ...] = ()
    scenario_family: str = ""
    expected_events: tuple[str, ...] = ()
    requires_core1_handoff: bool = False
    core1_handoff_enabled: bool = False

    @property
    def operator_trace(self) -> str:
        return ";".join(self.operators)

    @property
    def section_trace(self) -> str:
        return ";".join(self.sections)

    @property
    def expected_event_trace(self) -> str:
        return ";".join(self.expected_events)


@dataclass(frozen=True)
class SchedulerSelection:
    entry: CorpusEntry
    corpus_index: int
    weight: int
    total_weight: int
    policy: str = SFUZZ_SCHEDULER_POLICY
    focus_group: str = ""
    focus_deficit: int = 0
    bucket: str = ""
    operator_hint: str = ""


@dataclass(frozen=True)
class CoverageGroupSnapshot:
    covered: dict[str, int]
    total: dict[str, int]
    order: tuple[str, ...] = ()


@dataclass
class SchedulerRuntime:
    operator_credit: dict[str, int] = field(default_factory=dict)
    operator_attempts: dict[str, int] = field(default_factory=dict)
    operator_stall: dict[str, int] = field(default_factory=dict)
    family_credit: dict[str, int] = field(default_factory=dict)
    family_attempts: dict[str, int] = field(default_factory=dict)
    family_stall: dict[str, int] = field(default_factory=dict)
    group_credit: dict[str, int] = field(default_factory=dict)
    group_attempts: dict[str, int] = field(default_factory=dict)
    group_stall: dict[str, int] = field(default_factory=dict)
    hard_target_first_hit: dict[str, int] = field(default_factory=dict)


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


def seed_bool_tag(seed: Path, key: str) -> bool:
    try:
        parsed = read_sfuz_seed(seed)
    except Exception:
        return False
    prefix = f"{key}:"
    for tag in parsed.tags:
        if tag.strip().lower() == f"{prefix}true":
            return True
    return False


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
    new_points = 0
    for idx, value in enumerate(bitmap):
        covered = 1 if value else 0
        if covered and not accumulated[idx]:
            new_points += 1
            accumulated[idx] = 1
    return new_points


def accumulated_covered(accumulated: bytearray) -> int:
    return sum(1 for value in accumulated if value)


def group_trace(values: dict[str, int]) -> str:
    return ";".join(f"{key}:{values[key]}" for key in sorted(values) if values[key])


def group_accumulated_trace(values: dict[str, bytearray]) -> str:
    return group_trace({key: sum(1 for item in bitmap if item) for key, bitmap in values.items()})


def entry_group_affinity(entry: CorpusEntry) -> dict[str, int]:
    affinity: dict[str, int] = {}
    for raw_item in str(entry.seed_ir_targets or "").split(";"):
        item = raw_item.strip()
        if not item or ":" not in item:
            continue
        group, weight_text = item.split(":", 1)
        try:
            weight = int(weight_text)
        except ValueError:
            continue
        if weight > 0:
            affinity[group] = weight
    return affinity


def infer_entry_ir_fields(seed: Path) -> tuple[str, str]:
    try:
        ir = infer_seed_micro_ir(read_sfuz_seed(seed))
    except Exception:
        return "", ""
    return ir.target_trace, ir.event_trace


def infer_seed_semantic_fields(seed: Path) -> tuple[str, str, str]:
    try:
        parsed = read_sfuz_seed(seed)
    except Exception:
        return "", "", ""
    scenario_family = ""
    semantic_operator = ""
    for tag in parsed.tags:
        key, sep, value = tag.partition(":")
        if not sep:
            continue
        normalized_key = key.strip().lower()
        normalized_value = value.strip()
        if normalized_key == "scenario" and normalized_value:
            scenario_family = normalized_value
        elif normalized_key == "operator" and normalized_value:
            semantic_operator = normalized_value
    operator_trace = f"semantic.{semantic_operator}" if semantic_operator else ""
    section_trace = f"scenario:{scenario_family}" if scenario_family else ""
    scheduler_family = f"initial:{scenario_family}" if scenario_family else "initial"
    return operator_trace, section_trace, scheduler_family


def parse_coverage_group_snapshot(coverage: CoverageResult) -> CoverageGroupSnapshot:
    covered: dict[str, int] = {}
    total: dict[str, int] = {}
    order: list[str] = []
    sources = [item for item in str(coverage.coverage_source or "").split(";") if item]
    for source in sources:
        path = Path(source)
        if path.suffix != ".json" or not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        groups = payload.get("groups")
        if not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, dict):
                continue
            name = str(group.get("name") or "")
            if not name or name in {"all", "common"}:
                continue
            try:
                group_total = int(group.get("total", 0))
                group_covered = int(group.get("covered", 0))
            except (TypeError, ValueError):
                continue
            total[name] = max(total.get(name, 0), group_total)
            covered[name] = max(covered.get(name, 0), group_covered)
            if name not in {"all", "common", SFUZZ_NATIVE_GROUP} and name not in order:
                order.append(name)
    return CoverageGroupSnapshot(covered=covered, total=total, order=tuple(order))


def coverage_group_deficits(snapshot: CoverageGroupSnapshot) -> dict[str, int]:
    deficits: dict[str, int] = {}
    for group, total in snapshot.total.items():
        if total > 0:
            deficits[group] = max(0, total - snapshot.covered.get(group, 0))
    return deficits


def coverage_group_delta(
    bitmap: bytes | None,
    accumulated_by_group: dict[str, bytearray],
    snapshot: CoverageGroupSnapshot,
) -> tuple[dict[str, int], dict[str, int]]:
    if bitmap is None or not snapshot.order:
        return {}, {group: sum(1 for value in values if value) for group, values in accumulated_by_group.items()}
    ordered_groups = [group for group in snapshot.order if snapshot.total.get(group, 0) > 0]
    expected_bytes = sum(snapshot.total[group] for group in ordered_groups)
    if expected_bytes != len(bitmap):
        return {}, {group: sum(1 for value in values if value) for group, values in accumulated_by_group.items()}

    offset = 0
    new_by_group: dict[str, int] = {}
    accumulated_counts: dict[str, int] = {}
    for group in ordered_groups:
        width = snapshot.total[group]
        chunk = bitmap[offset : offset + width]
        offset += width
        group_accumulated = accumulated_by_group.setdefault(group, bytearray(width))
        if len(group_accumulated) != width:
            group_accumulated[:] = b"\x00" * width
        new_points = 0
        for idx, value in enumerate(chunk):
            covered = 1 if value else 0
            if covered and not group_accumulated[idx]:
                new_points += 1
                group_accumulated[idx] = 1
        new_by_group[group] = new_points
        accumulated_counts[group] = sum(1 for value in group_accumulated if value)
    return new_by_group, accumulated_counts


def accumulated_group_deficits(totals: dict[str, int], accumulated_counts: dict[str, int]) -> dict[str, int]:
    deficits: dict[str, int] = {}
    for group, total in totals.items():
        if group in {"all", "common", SFUZZ_NATIVE_GROUP}:
            continue
        if total > 0:
            deficits[group] = max(0, total - accumulated_counts.get(group, 0))
    return deficits


def update_runtime_feedback(
    runtime: SchedulerRuntime,
    entry: CorpusEntry,
    *,
    campaign_exec: int,
    new_bits: int,
    group_new_bits: dict[str, int],
) -> None:
    entry.execution_count += 1
    entry.total_new_coverage_bits += max(0, new_bits)
    if new_bits > 0:
        entry.no_new_coverage_streak = 0
    else:
        entry.no_new_coverage_streak += 1

    operator = semantic_operator_name(entry)
    if operator:
        runtime.operator_attempts[operator] = runtime.operator_attempts.get(operator, 0) + 1
        runtime.operator_credit[operator] = runtime.operator_credit.get(operator, 0) + max(0, new_bits)
        if new_bits > 0:
            runtime.operator_stall[operator] = 0
        else:
            runtime.operator_stall[operator] = runtime.operator_stall.get(operator, 0) + 1
        entry.semantic_operator_credit = runtime.operator_credit.get(operator, 0)
        entry.semantic_operator_stall = runtime.operator_stall.get(operator, 0)

    family = scenario_family_name(entry)
    if family:
        runtime.family_attempts[family] = runtime.family_attempts.get(family, 0) + 1
        runtime.family_credit[family] = runtime.family_credit.get(family, 0) + max(0, new_bits)
        if new_bits > 0:
            runtime.family_stall[family] = 0
        else:
            runtime.family_stall[family] = runtime.family_stall.get(family, 0) + 1
        entry.scenario_family_credit = runtime.family_credit.get(family, 0)
        entry.scenario_family_stall = runtime.family_stall.get(family, 0)

    first_hits: list[str] = []
    for group in SFUZZ_HARD_TARGET_GROUPS:
        if group_new_bits.get(group, 0) > 0 and group not in runtime.hard_target_first_hit:
            runtime.hard_target_first_hit[group] = campaign_exec
            first_hits.append(f"{group}:{campaign_exec}")
    if first_hits:
        entry.hard_target_first_hits = ";".join(first_hits)

    for group, points in group_new_bits.items():
        if points > 0:
            runtime.group_credit[group] = runtime.group_credit.get(group, 0) + points
            runtime.group_stall[group] = 0

    focus_group = str(entry.coverage_group_focus or "")
    if focus_group:
        runtime.group_attempts[focus_group] = runtime.group_attempts.get(focus_group, 0) + 1
        if group_new_bits.get(focus_group, 0) > 0:
            runtime.group_credit[focus_group] = runtime.group_credit.get(focus_group, 0) + group_new_bits[focus_group]
            runtime.group_stall[focus_group] = 0
        else:
            runtime.group_stall[focus_group] = runtime.group_stall.get(focus_group, 0) + 1


def retention_reason_for_run(run_outcome_text: str, new_bits: int, group_new_bits: dict[str, int]) -> tuple[bool, str]:
    if run_outcome_text == "bug_triggered":
        return True, "bug_signature"
    if any(group_new_bits.get(group, 0) > 0 for group in SFUZZ_HARD_TARGET_GROUPS):
        return True, "hard_target_hit"
    if new_bits > 0:
        return True, "new_coverage"
    return False, "not_interesting"


def entry_focus_from_deficits(entry: CorpusEntry, deficits: dict[str, int]) -> tuple[str, int]:
    affinity = entry_group_affinity(entry)
    best_group = ""
    best_score = 0
    best_deficit = 0
    for group, weight in affinity.items():
        deficit = deficits.get(group, 0)
        if deficit <= 0:
            continue
        priority = MICRO_GROUP_PRIORITY.get(group, 1)
        score = max(1, weight) * max(1, priority) * deficit
        if score > best_score:
            best_group = group
            best_score = score
            best_deficit = deficit
    return best_group, best_deficit


def semantic_operator_name(entry: CorpusEntry) -> str:
    for raw_item in str(entry.mutation_operators or "").split(";"):
        item = raw_item.strip()
        if item.startswith("semantic."):
            return item[len("semantic.") :]
    return ""


def scenario_family_name(entry: CorpusEntry) -> str:
    for raw_item in str(entry.mutation_sections or "").split(";"):
        item = raw_item.strip()
        if item.startswith("scenario:"):
            return item.split(":", 1)[1]
    raw_family = str(entry.scheduler_family or "")
    if ":" in raw_family:
        return raw_family.rsplit(":", 1)[1]
    return ""


def active_hard_target_groups(core1_handoff_enabled: bool) -> tuple[str, ...]:
    if core1_handoff_enabled:
        return SFUZZ_HARD_TARGET_GROUPS
    return tuple(group for group in SFUZZ_HARD_TARGET_GROUPS if group != "sfuzz_coherence")


def bounded_energy(new_bits: int, min_energy: int, max_energy: int) -> int:
    lo = max(1, min_energy)
    hi = max(lo, max_energy)
    if new_bits <= 0:
        return lo
    return min(hi, lo + new_bits.bit_length())


def normalized_mutation_budget(budget: int) -> int:
    return max(1, int(budget))


def scheduler_weight(entry: CorpusEntry, deficits: dict[str, int] | None = None) -> int:
    try:
        weight = max(1, int(entry.energy))
    except (TypeError, ValueError):
        weight = 1
    if not deficits:
        return weight
    focus_group, focus_deficit = entry_focus_from_deficits(entry, deficits)
    if focus_group:
        affinity = entry_group_affinity(entry).get(focus_group, 1)
        scale = 1 + min(16, max(1, focus_deficit).bit_length()) + min(8, affinity)
        weight *= scale
    return max(1, weight)


def choose_weighted_index(indices: list[int], weights: list[int], rng: random.Random) -> tuple[int, int, int]:
    if not indices:
        raise ValueError("SFuzz scheduler requires a non-empty candidate set")
    total = sum(max(1, weight) for weight in weights)
    ticket = rng.randrange(total)
    cursor = 0
    for idx, weight in zip(indices, weights):
        normalized = max(1, weight)
        cursor += normalized
        if ticket < cursor:
            return idx, normalized, total
    return indices[-1], max(1, weights[-1]), total


def select_weighted_parent(
    corpus: list[CorpusEntry],
    rng: random.Random,
    deficits: dict[str, int] | None = None,
) -> SchedulerSelection:
    if not corpus:
        raise ValueError("SFuzz scheduler requires a non-empty corpus")
    weights = [scheduler_weight(entry, deficits) for entry in corpus]
    total = sum(weights)
    ticket = rng.randrange(total)
    cursor = 0
    for idx, weight in enumerate(weights):
        cursor += weight
        if ticket < cursor:
            focus_group, focus_deficit = entry_focus_from_deficits(corpus[idx], deficits or {})
            return SchedulerSelection(corpus[idx], idx, weight, total, SFUZZ_SCHEDULER_POLICY, focus_group, focus_deficit)
    last_idx = len(corpus) - 1
    focus_group, focus_deficit = entry_focus_from_deficits(corpus[last_idx], deficits or {})
    return SchedulerSelection(
        corpus[last_idx],
        last_idx,
        weights[last_idx],
        total,
        SFUZZ_SCHEDULER_POLICY,
        focus_group,
        focus_deficit,
    )


def hard_target_focus_group(
    deficits: dict[str, int],
    runtime: SchedulerRuntime,
    hard_targets: tuple[str, ...] = SFUZZ_HARD_TARGET_GROUPS,
) -> tuple[str, int]:
    best_group = ""
    best_score = 0
    best_deficit = 0
    for group in hard_targets:
        deficit = deficits.get(group, 0)
        if deficit <= 0:
            continue
        priority = MICRO_GROUP_PRIORITY.get(group, 1)
        first_hit_bonus = 3 if group not in runtime.hard_target_first_hit else 1
        stall_penalty = 1 + min(8, runtime.group_stall.get(group, 0))
        attempts = runtime.group_attempts.get(group, 0)
        exploration_bonus = 2 if attempts == 0 else 1
        score = (priority * deficit * first_hit_bonus * exploration_bonus) // stall_penalty
        if score > best_score:
            best_group = group
            best_score = score
            best_deficit = deficit
    return best_group, best_deficit


def semantic_bandit_weight(
    entry: CorpusEntry,
    deficits: dict[str, int],
    runtime: SchedulerRuntime,
    forced_focus_group: str = "",
) -> int:
    weight = scheduler_weight(entry, deficits)
    focus_group, focus_deficit = entry_focus_from_deficits(entry, deficits)
    if forced_focus_group:
        affinity = entry_group_affinity(entry).get(forced_focus_group, 0)
        if affinity:
            focus_group = forced_focus_group
            focus_deficit = deficits.get(forced_focus_group, 0)
            weight += max(1, affinity) * max(1, MICRO_GROUP_PRIORITY.get(forced_focus_group, 1))

    if focus_group in SFUZZ_HARD_TARGET_GROUPS and focus_deficit > 0:
        weight *= 2
        if focus_group not in runtime.hard_target_first_hit:
            weight *= 2
    if focus_group:
        weight = max(1, weight // (1 + min(8, runtime.group_stall.get(focus_group, 0))))

    operator = semantic_operator_name(entry)
    if operator:
        credit = runtime.operator_credit.get(operator, 0)
        attempts = runtime.operator_attempts.get(operator, 0)
        stall = runtime.operator_stall.get(operator, 0)
        weight += min(64, credit.bit_length() * 4)
        if attempts <= 1:
            weight += 8
        weight = max(1, weight // (1 + min(4, stall)))

    family = scenario_family_name(entry)
    if family:
        credit = runtime.family_credit.get(family, 0)
        attempts = runtime.family_attempts.get(family, 0)
        stall = runtime.family_stall.get(family, 0)
        weight += min(64, credit.bit_length() * 3)
        if attempts <= 1:
            weight += 8
        weight = max(1, weight // (1 + min(8, stall)))

    if entry.no_new_coverage_streak:
        weight = max(1, weight // (1 + min(4, entry.no_new_coverage_streak)))
    if entry.execution_count:
        weight = max(1, weight // (1 + min(3, entry.execution_count // 4)))
    return max(1, weight)


def select_semantic_bandit_parent(
    corpus: list[CorpusEntry],
    rng: random.Random,
    deficits: dict[str, int] | None,
    runtime: SchedulerRuntime,
    core1_handoff_enabled: bool = False,
) -> SchedulerSelection:
    if not corpus:
        raise ValueError("SFuzz scheduler requires a non-empty corpus")
    active_deficits = deficits or {}
    roll = rng.randrange(100)
    indices = list(range(len(corpus)))
    forced_focus = ""
    operator_hint = ""
    bucket = "credit"

    if active_deficits and roll < 25:
        forced_focus, _forced_deficit = hard_target_focus_group(
            active_deficits,
            runtime,
            active_hard_target_groups(core1_handoff_enabled),
        )
        if forced_focus:
            affinity_indices = [
                idx for idx, entry in enumerate(corpus) if entry_group_affinity(entry).get(forced_focus, 0) > 0
            ]
            if affinity_indices:
                indices = affinity_indices
            bucket = f"hard-target:{forced_focus}"
    elif roll < 45:
        family_to_indices: dict[str, list[int]] = {}
        for idx, entry in enumerate(corpus):
            family = scenario_family_name(entry)
            if family:
                family_to_indices.setdefault(family, []).append(idx)
        if family_to_indices:
            least_attempts = min(runtime.family_attempts.get(family, 0) for family in family_to_indices)
            families = sorted(family for family in family_to_indices if runtime.family_attempts.get(family, 0) == least_attempts)
            family = families[rng.randrange(len(families))]
            indices = family_to_indices[family]
            bucket = f"family-explore:{family}"
            try:
                operator_hint = family_default_operator(family)
            except ValueError:
                operator_hint = ""

    weights = [semantic_bandit_weight(corpus[idx], active_deficits, runtime, forced_focus) for idx in indices]
    selected_idx, selected_weight, total = choose_weighted_index(indices, weights, rng)
    focus_group, focus_deficit = entry_focus_from_deficits(corpus[selected_idx], active_deficits)
    if forced_focus:
        focus_group = forced_focus
        focus_deficit = active_deficits.get(forced_focus, 0)
    return SchedulerSelection(
        corpus[selected_idx],
        selected_idx,
        selected_weight,
        total,
        SEMANTIC_BANDIT_SCHEDULER_POLICY,
        focus_group,
        focus_deficit,
        bucket,
        operator_hint,
    )


def select_baseline_parent(corpus: list[CorpusEntry], mutation_counter: int) -> SchedulerSelection:
    if not corpus:
        raise ValueError("SFuzz scheduler requires a non-empty corpus")
    idx = mutation_counter % len(corpus)
    return SchedulerSelection(corpus[idx], idx, 1, len(corpus), BASELINE_SCHEDULER_POLICY)


def select_parent(
    corpus: list[CorpusEntry],
    rng: random.Random,
    policy: str,
    mutation_counter: int,
    deficits: dict[str, int] | None = None,
    runtime: SchedulerRuntime | None = None,
    core1_handoff_enabled: bool = False,
) -> SchedulerSelection:
    normalized = (policy or WEIGHTED_SCHEDULER_POLICY).replace("-", "_")
    if normalized in {"baseline", "baseline_fifo", "fifo"}:
        return select_baseline_parent(corpus, mutation_counter)
    if normalized in {"semantic_bandit", "semantic", "bandit"}:
        return select_semantic_bandit_parent(
            corpus,
            rng,
            deficits,
            runtime or SchedulerRuntime(),
            core1_handoff_enabled,
        )
    if normalized in {"weighted", "weighted_innovation", "coverage_weighted_energy"}:
        selected = select_weighted_parent(corpus, rng, deficits)
        return SchedulerSelection(
            selected.entry,
            selected.corpus_index,
            selected.weight,
            selected.total_weight,
            WEIGHTED_SCHEDULER_POLICY,
            selected.focus_group,
            selected.focus_deficit,
            selected.bucket,
        )
    raise ValueError(f"unsupported SFuzz scheduler policy: {policy}")


def ensure_core0_program(core0: bytearray) -> None:
    if not core0:
        core0.extend(DEFAULT_CORE0_PROG)


def ensure_program_payload(payload: bytearray) -> None:
    if not payload:
        payload.extend(DEFAULT_CORE0_PROG)


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


def apply_program_mutation_operator(payload: bytearray, operator: str, rng: random.Random) -> None:
    if operator not in SFUZZ_MUTATION_OPERATORS:
        raise ValueError(f"unsupported SFuzz mutation operator: {operator}")
    ensure_program_payload(payload)
    if operator == "bitflip_byte":
        idx = rng.randrange(len(payload))
        payload[idx] ^= 1 << rng.randrange(8)
    elif operator == "overwrite_byte":
        idx = rng.randrange(len(payload))
        payload[idx] = rng.randrange(256)
    elif operator == "bitflip_word":
        if len(payload) < 4:
            raise ValueError("bitflip_word requires at least 4 bytes")
        word_count = len(payload) // 4
        word_idx = rng.randrange(word_count)
        start = word_idx * 4
        word = int.from_bytes(payload[start : start + 4], "little")
        word ^= 1 << rng.randrange(32)
        payload[start : start + 4] = word.to_bytes(4, "little")
    elif operator == "delete_range":
        if len(payload) <= 4:
            raise ValueError("delete_range requires more than 4 bytes")
        start = rng.randrange(len(payload))
        width = rng.randrange(1, min(8, len(payload) - start) + 1)
        del payload[start : min(len(payload), start + width)]
    elif operator == "insert_random_bytes":
        idx = rng.randrange(len(payload) + 1)
        payload[idx:idx] = rng.randbytes(rng.randrange(1, 9))


def apply_sfuz_mutation_operator(core0: bytearray, operator: str, rng: random.Random) -> None:
    if operator not in SFUZZ_MUTATION_OPERATORS:
        raise ValueError(f"unsupported SFuzz mutation operator: {operator}")
    ensure_core0_program(core0)
    apply_program_mutation_operator(core0, operator, rng)


def mutate_core0_program(core0: bytearray, rng: random.Random, budget: int) -> MutationSummary:
    mutation_budget = normalized_mutation_budget(budget)
    operators: list[str] = []
    ensure_core0_program(core0)
    for _ in range(mutation_budget):
        operator = choose_mutation_operator(core0, rng)
        apply_sfuz_mutation_operator(core0, operator, rng)
        operators.append(operator)
    return MutationSummary(mutation_budget, tuple(operators), ("core0",) * len(operators))


def normalize_mutation_sections(sections: str | tuple[str, ...] | list[str] | None) -> tuple[str, ...]:
    if sections is None:
        return ("core0",)
    if isinstance(sections, str):
        raw_items = [item.strip() for item in sections.replace(";", ",").split(",")]
    else:
        raw_items = [str(item).strip() for item in sections]
    selected: list[str] = []
    for item in raw_items:
        if not item:
            continue
        normalized = item.lower().replace("-", "_")
        if normalized == "all":
            selected.extend(SFUZZ_MUTATION_SECTIONS)
            continue
        if normalized not in SFUZZ_MUTATION_SECTIONS:
            raise ValueError(f"unsupported SFuzz mutation section: {item}")
        selected.append(normalized)
    if not selected:
        return ("core0",)
    deduped: list[str] = []
    for section in selected:
        if section not in deduped:
            deduped.append(section)
    return tuple(deduped)


def plan_sections_for_focus(
    base_sections: str | tuple[str, ...] | list[str] | None,
    focus_group: str,
    seed_ir_targets: str = "",
) -> tuple[str, ...]:
    allowed = normalize_mutation_sections(base_sections)
    planned: list[str] = []
    for section in MICRO_GROUP_SECTION_HINTS.get(focus_group, ()):
        if section in allowed and section not in planned:
            planned.append(section)
    if not planned and seed_ir_targets:
        synthetic = CorpusEntry(0, Path("seed.sfuz"), "seed", "seed", 1)
        synthetic.seed_ir_targets = seed_ir_targets
        for group, _weight in sorted(entry_group_affinity(synthetic).items(), key=lambda item: (-item[1], item[0])):
            for section in MICRO_GROUP_SECTION_HINTS.get(group, ()):
                if section in allowed and section not in planned:
                    planned.append(section)
    for section in allowed:
        if section not in planned:
            planned.append(section)
    return tuple(planned) if planned else allowed


def choose_program_operator(payload: bytearray, rng: random.Random) -> str:
    ensure_program_payload(payload)
    operators = mutation_operator_selection_pool(payload)
    return operators[rng.randrange(len(operators))]


def mutate_program_payload(section: str, payload: bytearray, rng: random.Random) -> str:
    operator = choose_program_operator(payload, rng)
    apply_program_mutation_operator(payload, operator, rng)
    return f"{section}.{operator}"


def random_shared_segment(rng: random.Random) -> tuple[int, bytes]:
    base = 0x80000000 + (rng.randrange(0, 256) * 0x40)
    size = rng.randrange(1, 33)
    return base, rng.randbytes(size)


def mutate_shared_segments(segments: list[tuple[int, bytes]], rng: random.Random) -> str:
    if not segments:
        operator = "shared_insert_segment"
    else:
        operator = SFUZZ_SHARED_MUTATION_OPERATORS[rng.randrange(len(SFUZZ_SHARED_MUTATION_OPERATORS))]
    if operator == "shared_insert_segment":
        segments.append(random_shared_segment(rng))
    elif operator == "shared_delete_segment":
        if len(segments) <= 1:
            operator = "shared_insert_segment"
            segments.append(random_shared_segment(rng))
        else:
            del segments[rng.randrange(len(segments))]
    elif operator == "shared_mutate_base":
        idx = rng.randrange(len(segments))
        base, data = segments[idx]
        delta = (rng.randrange(-16, 17) * 0x40)
        segments[idx] = (max(0, base + delta), data)
    else:
        idx = rng.randrange(len(segments))
        base, data = segments[idx]
        payload = bytearray(data)
        ensure_program_payload(payload)
        if operator == "shared_bitflip_byte":
            pos = rng.randrange(len(payload))
            payload[pos] ^= 1 << rng.randrange(8)
        elif operator == "shared_overwrite_byte":
            pos = rng.randrange(len(payload))
            payload[pos] = rng.randrange(256)
        elif operator == "shared_insert_random_bytes":
            pos = rng.randrange(len(payload) + 1)
            payload[pos:pos] = rng.randbytes(rng.randrange(1, 9))
        elif operator == "shared_delete_range":
            if len(payload) <= 1:
                operator = "shared_insert_random_bytes"
                pos = rng.randrange(len(payload) + 1)
                payload[pos:pos] = rng.randbytes(rng.randrange(1, 9))
            else:
                start = rng.randrange(len(payload))
                width = rng.randrange(1, min(8, len(payload) - start) + 1)
                del payload[start : min(len(payload), start + width)]
        else:
            raise ValueError(f"unsupported SFuzz shared mutation operator: {operator}")
        segments[idx] = (base, bytes(payload))
    return f"shared.{operator}"


def random_interrupt_event(rng: random.Random) -> bytes:
    return rng.randbytes(24)


def mutate_interrupt_plan(events: list[bytearray], rng: random.Random) -> str:
    if not events:
        operator = "interrupt_insert_event"
    else:
        operator = SFUZZ_INTERRUPT_MUTATION_OPERATORS[rng.randrange(len(SFUZZ_INTERRUPT_MUTATION_OPERATORS))]
    if operator == "interrupt_insert_event":
        events.append(bytearray(random_interrupt_event(rng)))
    elif operator == "interrupt_delete_event":
        if len(events) <= 1:
            operator = "interrupt_insert_event"
            events.append(bytearray(random_interrupt_event(rng)))
        else:
            del events[rng.randrange(len(events))]
    elif operator == "interrupt_bitflip_byte":
        idx = rng.randrange(len(events))
        pos = rng.randrange(24)
        events[idx][pos] ^= 1 << rng.randrange(8)
    elif operator == "interrupt_overwrite_byte":
        idx = rng.randrange(len(events))
        pos = rng.randrange(24)
        events[idx][pos] = rng.randrange(256)
    else:
        raise ValueError(f"unsupported SFuzz interrupt mutation operator: {operator}")
    return f"interrupt.{operator}"


def mutate_sfuz_legacy(
    parent: Path,
    output: Path,
    rng: random.Random,
    budget: int,
    sections: str | tuple[str, ...] | list[str] | None = None,
) -> MutationSummary:
    seed = read_sfuz_seed(parent)
    core0 = bytearray(seed.core0_prog)
    core1 = bytearray(seed.core1_prog)
    shared = [(base, bytes(data)) for base, data in seed.shared_mem_init]
    interrupts = [bytearray(event) for event in seed.interrupt_plan_raw]
    mutation_budget = normalized_mutation_budget(budget)
    mutation_sections = normalize_mutation_sections(sections)
    operators: list[str] = []
    section_trace: list[str] = []
    for _ in range(mutation_budget):
        section = mutation_sections[rng.randrange(len(mutation_sections))]
        if section == "core0":
            operator = mutate_program_payload("core0", core0, rng)
        elif section == "core1":
            operator = mutate_program_payload("core1", core1, rng)
        elif section == "shared":
            operator = mutate_shared_segments(shared, rng)
        elif section == "interrupt":
            operator = mutate_interrupt_plan(interrupts, rng)
        else:
            raise ValueError(f"unsupported SFuzz mutation section: {section}")
        operators.append(operator)
        section_trace.append(section)
    summary = MutationSummary(mutation_budget, tuple(operators), tuple(section_trace))
    mutated = SfuzSeed(
        core0_prog=bytes(core0),
        core1_prog=bytes(core1),
        shared_mem_init=shared,
        interrupt_plan_raw=[bytes(event) for event in interrupts],
        name=f"{seed.name or parent.stem}.mut",
        description=f"mutated from {parent}",
        tags=[*seed.tags, "sfuzz-online-mutated"],
    )
    write_sfuz_seed(output, mutated)
    return summary


def mutate_sfuz(
    parent: Path,
    output: Path,
    rng: random.Random,
    budget: int,
    sections: str | tuple[str, ...] | list[str] | None = None,
    *,
    focus_group: str = "",
    seed_ir_targets: str = "",
    semantic: bool = True,
    core1_handoff_enabled: bool = False,
    target_min_wall_time_sec: int = 0,
    mutation_index: int = 0,
    stalled_operators: tuple[str, ...] = (),
    operator_hint: str = "",
) -> MutationSummary:
    if not semantic:
        return mutate_sfuz_legacy(parent, output, rng, budget, sections)

    mutation_budget = normalized_mutation_budget(budget)
    if operator_hint and operator_hint not in set(stalled_operators):
        operator = operator_hint
    else:
        operator = choose_semantic_operator(
            focus_group,
            seed_ir_targets,
            rng=rng,
            core1_handoff_enabled=core1_handoff_enabled,
            stalled_operators=stalled_operators,
        )
    scenario = scenario_from_operator(
        operator,
        variant=(mutation_index * 17) + rng.randrange(997),
        rng=rng,
        core1_handoff_enabled=core1_handoff_enabled,
        runtime_profile="long" if target_min_wall_time_sec > 0 else "short",
        target_min_wall_time_sec=max(0, target_min_wall_time_sec),
    )

    write_scenario_artifacts(output, scenario)
    return MutationSummary(
        mutation_budget,
        (f"semantic.{operator}",),
        (f"scenario:{scenario.scenario_family}",),
        scenario_family=scenario.scenario_family,
        expected_events=scenario.expected_micro_events,
        requires_core1_handoff=scenario.requires_core1_handoff,
        core1_handoff_enabled=scenario.core1_handoff_enabled,
    )


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
    native_feedback = coverage.coverage_name == f"sfuzz_firrtl.{SFUZZ_NATIVE_GROUP}"
    comparison_tier = "T2_sfuzz_native_online" if native_feedback else "T0_smoke"
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
        "native_feedback": native_feedback,
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
    group_new_bits: dict[str, int],
    group_accumulated_bits: dict[str, int],
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
        "mutation_sections": entry.mutation_sections,
        "seed_ir_targets": entry.seed_ir_targets,
        "seed_event_plan": entry.seed_event_plan,
        "coverage_group_focus": entry.coverage_group_focus,
        "coverage_group_deficit": entry.coverage_group_deficit,
        "coverage_group_new_bits": group_trace(group_new_bits),
        "coverage_group_accumulated_bits": group_trace(group_accumulated_bits),
        "hard_target_first_hits": entry.hard_target_first_hits,
        "scheduler_policy": entry.scheduler_policy,
        "scheduler_family": entry.scheduler_family,
        "scheduler_bucket": entry.scheduler_bucket,
        "innovation_enabled": entry.innovation_enabled,
        "scheduler_corpus_index": entry.scheduler_corpus_index,
        "scheduler_weight": entry.scheduler_weight,
        "scheduler_total_weight": entry.scheduler_total_weight,
        "semantic_operator_credit": entry.semantic_operator_credit,
        "semantic_operator_stall": entry.semantic_operator_stall,
        "scenario_family_credit": entry.scenario_family_credit,
        "scenario_family_stall": entry.scenario_family_stall,
        "retained": retained,
        "retention_reason": retention_reason,
        "comparison_tier": run["comparison_tier"],
        "paper_faithful": run["native_feedback"],
        "coverage_backend": "sfuzz_native" if run["native_feedback"] else run["coverage_backend"],
        "coverage_bitmap_semantics": SFUZZ_COVERAGE_BITMAP_SEMANTICS if run["native_feedback"] else "",
        "common_coverage_backend": run["coverage_backend"],
        "common_coverage_name": coverage.coverage_name,
        "common_coverage_value": coverage.coverage_value,
        "common_coverage_source": coverage.coverage_source,
        "common_coverage_status": coverage.coverage_status,
        "common_coverage_covered": coverage.covered if coverage.covered is not None else "",
        "common_coverage_total": coverage.total if coverage.total is not None else "",
        "new_coverage_bits": new_bits,
        "accumulated_covered_bits": accumulated_covered(accumulated),
        "required_native_abi": "" if run["native_feedback"] else "SFUZZ.native",
        "wall_time_sec": round(run["result"].wall_time_sec, 3),
        "target_min_wall_time_sec": entry.target_min_wall_time_sec,
        "short_run": bool(entry.target_min_wall_time_sec and run["result"].wall_time_sec < entry.target_min_wall_time_sec),
        "vcs_cycles": run["info"].cycles if run["info"].cycles is not None else "",
        "vcs_cpu_time_sec": run["info"].vcs_cpu_time_sec,
        "vcs_sim_time_ps": run["info"].vcs_sim_time_ps,
        "max_cycle_exceeded": run["info"].max_cycle_exceeded,
        "run_outcome": run["run_outcome"],
        "t0_smoke_pass": run["t0_smoke_pass"],
        "exit_code": run["result"].returncode,
        "vcs_report_seen": run["info"].vcs_report_seen,
        "sfuz_expansion_seen": run["info"].sfuz_expansion_seen,
        "sfuzz_core0_staged": run["info"].sfuzz_core0_staged,
        "sfuzz_core1_staged": run["info"].sfuzz_core1_staged,
        "sfuzz_core1_entry": run["info"].sfuzz_core1_entry,
        "sfuzz_core1_payload_size": run["info"].sfuzz_core1_payload_size if run["info"].sfuzz_core1_payload_size is not None else "",
        "core1_executed": run["info"].sfuzz_core1_executed,
        "core1_handoff_reason": run["info"].sfuzz_core1_handoff_reason,
        "requires_core1_handoff": entry.requires_core1_handoff,
        "formal_multicore_result": bool(
            not entry.requires_core1_handoff
            or (entry.core1_handoff_enabled and run["info"].sfuzz_core1_executed)
        ),
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
        ir_targets, event_plan = infer_entry_ir_fields(seed)
        operator_trace, section_trace, scheduler_family = infer_seed_semantic_fields(seed)
        entries.append(
            CorpusEntry(
                corpus_id=idx,
                path=seed,
                seed_name=seed_name,
                category=seed_category(seed, seed_name),
                energy=max(1, getattr(args, "min_energy", 1)),
                mutation_operators=operator_trace,
                mutation_sections=section_trace,
                seed_ir_targets=ir_targets,
                seed_event_plan=event_plan,
                scheduler_family=scheduler_family,
                innovation_enabled=False,
                requires_core1_handoff=seed_bool_tag(seed, "requires_core1_handoff"),
                core1_handoff_enabled=getattr(args, "enable_core1_handoff", False),
                target_min_wall_time_sec=getattr(args, "target_min_wall_time_sec", 0),
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
            args.firrtl_cov = SFUZZ_NATIVE_COVERAGE_NAME

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
    accumulated_by_group: dict[str, bytearray] = {}
    accumulated_group_counts: dict[str, int] = {}
    group_totals: dict[str, int] = {}
    group_deficits: dict[str, int] = {}
    scheduler_runtime = SchedulerRuntime()
    rng = random.Random(getattr(args, "rng_seed", 1))
    campaign_runs = len(corpus) if getattr(args, "batch_replay", False) else max(1, getattr(args, "campaign_runs", 8))
    next_corpus_id = len(corpus)
    mutation_counter = 0

    for exec_idx in range(1, campaign_runs + 1):
        if getattr(args, "batch_replay", False):
            entry = corpus[exec_idx - 1]
            entry.scheduler_policy = "batch_replay"
            entry.scheduler_family = "batch_replay"
            entry.innovation_enabled = False
        elif exec_idx <= len(corpus):
            entry = corpus[exec_idx - 1]
            entry.scheduler_policy = "initial_corpus"
            entry.scheduler_family = "initial"
            entry.innovation_enabled = False
        else:
            scheduler_policy = getattr(args, "scheduler_policy", WEIGHTED_SCHEDULER_POLICY)
            scheduling_deficits = {} if getattr(args, "disable_scenario_aware_scheduling", False) else group_deficits
            scheduled = select_parent(
                corpus,
                rng,
                scheduler_policy,
                mutation_counter,
                scheduling_deficits,
                scheduler_runtime,
                getattr(args, "enable_core1_handoff", False),
            )
            parent = scheduled.entry
            mutation_counter += 1
            mutated_path = generated_dir / f"sfuzz-mut-{mutation_counter:04d}.sfuz"
            mutation_sections = plan_sections_for_focus(
                getattr(args, "mutation_sections", "core0,core1,shared,interrupt"),
                scheduled.focus_group,
                parent.seed_ir_targets,
            )
            mutation = mutate_sfuz(
                parent.path,
                mutated_path,
                rng,
                parent.energy,
                mutation_sections,
                focus_group="" if getattr(args, "disable_scenario_aware_scheduling", False) else scheduled.focus_group,
                seed_ir_targets="" if getattr(args, "disable_scenario_aware_scheduling", False) else parent.seed_ir_targets,
                semantic=not getattr(args, "disable_semantic_mutation", False),
                core1_handoff_enabled=getattr(args, "enable_core1_handoff", False),
                target_min_wall_time_sec=getattr(args, "target_min_wall_time_sec", 0),
                mutation_index=mutation_counter,
                stalled_operators=tuple(
                    operator
                    for operator, stall in scheduler_runtime.operator_stall.items()
                    if stall >= 3
                ),
                operator_hint=scheduled.operator_hint,
            )
            seed_name = read_seed_metadata_name(mutated_path)
            ir_targets, event_plan = infer_entry_ir_fields(mutated_path)
            scheduler_family = "baseline" if scheduled.policy == BASELINE_SCHEDULER_POLICY else "innovation"
            if mutation.scenario_family:
                event_plan = ";".join(item for item in [event_plan, mutation.expected_event_trace] if item)
            entry = CorpusEntry(
                corpus_id=next_corpus_id,
                path=mutated_path,
                seed_name=seed_name,
                category=seed_category(mutated_path, seed_name),
                energy=parent.energy,
                seed_ir_targets=ir_targets,
                seed_event_plan=event_plan,
                coverage_group_focus=scheduled.focus_group,
                coverage_group_deficit=scheduled.focus_deficit,
                parent_corpus_id=parent.corpus_id,
                mutation_index=mutation_counter,
                mutation_budget=mutation.budget,
                mutation_operators=mutation.operator_trace,
                mutation_sections=mutation.section_trace,
                scheduler_policy=scheduled.policy,
                scheduler_family=f"{scheduler_family}:{mutation.scenario_family}" if mutation.scenario_family else scheduler_family,
                scheduler_bucket=scheduled.bucket,
                innovation_enabled=scheduler_family == "innovation" and not getattr(args, "disable_semantic_mutation", False),
                scheduler_corpus_index=scheduled.corpus_index,
                scheduler_weight=scheduled.weight,
                scheduler_total_weight=scheduled.total_weight,
                requires_core1_handoff=mutation.requires_core1_handoff,
                core1_handoff_enabled=mutation.core1_handoff_enabled,
                target_min_wall_time_sec=getattr(args, "target_min_wall_time_sec", 0),
            )
            next_corpus_id += 1

        case_name = f"{slugify(args.case_prefix)}-{exec_idx:04d}-{slugify(entry.seed_name)}"
        run = run_one(args, ctx, runs_dir, logs_dir, entry.path, case_name)
        bitmap = read_bitmap(run["coverage"])
        new_bits = coverage_delta(bitmap, accumulated)
        snapshot = parse_coverage_group_snapshot(run["coverage"])
        if snapshot.total:
            for group, total in snapshot.total.items():
                if group not in {"all", "common", SFUZZ_NATIVE_GROUP}:
                    group_totals[group] = max(group_totals.get(group, 0), total)
        group_new_bits, accumulated_group_counts = coverage_group_delta(bitmap, accumulated_by_group, snapshot)
        if snapshot.total:
            accumulated_deficits = accumulated_group_deficits(group_totals, accumulated_group_counts)
            group_deficits = accumulated_deficits or coverage_group_deficits(snapshot)
        update_runtime_feedback(
            scheduler_runtime,
            entry,
            campaign_exec=exec_idx,
            new_bits=new_bits,
            group_new_bits=group_new_bits,
        )
        retained, retention_reason = retention_reason_for_run(run["run_outcome"], new_bits, group_new_bits)
        if retained:
            entry.energy = bounded_energy(new_bits, args.min_energy, args.max_energy)
            focus_group, focus_deficit = entry_focus_from_deficits(entry, group_deficits)
            entry.coverage_group_focus = focus_group
            entry.coverage_group_deficit = focus_deficit
            if entry not in corpus:
                corpus.append(entry)
        notes = (
            "online SFuzz loop; SFUZZ.native group deficits drive corpus retention and parent selection; "
            f"semantic_mutation={not getattr(args, 'disable_semantic_mutation', False)}; "
            f"scenario_aware_scheduling={not getattr(args, 'disable_scenario_aware_scheduling', False)}; "
            f"core1_handoff_enabled={getattr(args, 'enable_core1_handoff', False)}; "
            "two-core AMO/fence/coherence scenarios are tagged fallback until LinkNan core1 handoff is enabled; "
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
                group_new_bits=group_new_bits,
                group_accumulated_bits=accumulated_group_counts,
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
        {
            "fuzzer": "sfuzz",
            "mode": "batch_replay" if getattr(args, "batch_replay", False) else "online",
            "scheduler_policy": getattr(args, "scheduler_policy", WEIGHTED_SCHEDULER_POLICY),
            "mutation_sections": getattr(args, "mutation_sections", "core0,core1,shared,interrupt"),
            "semantic_mutation": not getattr(args, "disable_semantic_mutation", False),
            "scenario_aware_scheduling": not getattr(args, "disable_scenario_aware_scheduling", False),
            "core1_handoff_enabled": getattr(args, "enable_core1_handoff", False),
            "coverage_bitmap_semantics": SFUZZ_COVERAGE_BITMAP_SEMANTICS,
            "coverage_group_deficits": group_trace(group_deficits),
            "coverage_group_accumulated_bits": group_accumulated_trace(accumulated_by_group),
            "hard_target_first_hits": group_trace(scheduler_runtime.hard_target_first_hit),
            "semantic_operator_credit": group_trace(scheduler_runtime.operator_credit),
            "semantic_operator_stall": group_trace(scheduler_runtime.operator_stall),
            "scenario_family_credit": group_trace(scheduler_runtime.family_credit),
            "scenario_family_stall": group_trace(scheduler_runtime.family_stall),
            "coverage_group_credit": group_trace(scheduler_runtime.group_credit),
            "coverage_group_stall": group_trace(scheduler_runtime.group_stall),
            "baseline_policy": BASELINE_SCHEDULER_POLICY,
            "innovation_policy": WEIGHTED_SCHEDULER_POLICY,
            "semantic_bandit_policy": SEMANTIC_BANDIT_SCHEDULER_POLICY,
        },
    )
    return 0
