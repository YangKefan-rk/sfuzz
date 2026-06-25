from __future__ import annotations

import random
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from linknan.methods.sfuzz import (  # noqa: E402
    BASELINE_SCHEDULER_POLICY,
    DEFAULT_CORE0_PROG,
    SFUZZ_FIELDS,
    CorpusEntry,
    SchedulerRuntime,
    apply_sfuz_mutation_operator,
    append_simv_arg,
    available_mutation_operators,
    bounded_energy,
    coverage_delta,
    coverage_group_delta,
    accumulated_covered,
    coverage_group_deficits,
    hard_target_focus_group,
    infer_seed_semantic_fields,
    mutate_core0_program,
    mutate_sfuz,
    mutation_operator_selection_pool,
    normalize_mutation_sections,
    parse_coverage_group_snapshot,
    plan_sections_for_focus,
    select_baseline_parent,
    select_parent,
    select_semantic_bandit_parent,
    select_weighted_parent,
    semantic_operator_name,
    scheduler_weight,
    update_runtime_feedback,
)
from linknan.seeds import SfuzSeed, infer_seed_micro_ir, read_sfuz_seed, write_sfuz_seed  # noqa: E402
from linknan.sfuzz_scenarios import (  # noqa: E402
    SCENARIO_FAMILIES,
    choose_semantic_operator,
    generate_scenario,
    generate_scenario_corpus,
    scenario_from_operator,
    seed_from_scenario,
    write_scenario_artifacts,
)
from linknan.vcs import CoverageResult  # noqa: E402
from linknan.vcs import (  # noqa: E402
    normalize_firrtl_coverage_name,
    requested_firrtl_groups,
    scan_vcs_logs,
    simv_compiled_without_difftest,
)
from linknan.config import context_from_config  # noqa: E402


class FixedTicketRng:
    def __init__(self, ticket: int) -> None:
        self.ticket = ticket

    def randrange(self, stop: int) -> int:
        if not 0 <= self.ticket < stop:
            raise AssertionError(f"ticket {self.ticket} outside randrange({stop})")
        return self.ticket


class SfuzzMutationTests(unittest.TestCase):
    def test_seed_micro_ir_extracts_microarchitectural_intent(self) -> None:
        seed = SfuzSeed(
            core0_prog=bytes.fromhex(
                "03010000"  # load
                "23200000"  # store
                "63000000"  # branch
                "73000000"  # ecall
            ),
            core1_prog=bytes.fromhex("2f200000"),
            shared_mem_init=[(0x80000000, b"a"), (0x80000000 + 8, b"b")],
            interrupt_plan_raw=[b"\x00" * 24],
            name="mmu-branch-seed",
            description="cache redirect exception",
            tags=["mshr"],
        )

        ir = infer_seed_micro_ir(seed)

        self.assertIn("core0:memory_stream", ir.event_plan)
        self.assertIn("core0:control_redirect", ir.event_plan)
        self.assertIn("core0:privileged_exception", ir.event_plan)
        self.assertIn("core1:atomic_resource", ir.event_plan)
        self.assertIn("shared:cacheline_alias", ir.event_plan)
        self.assertGreater(ir.group_affinity["memory_event"], ir.group_affinity["ready_valid"])
        self.assertIn("exception_event", ir.group_affinity)

    def test_seed_micro_ir_uses_native_scenario_target_tags(self) -> None:
        seed = SfuzSeed(
            core0_prog=bytes.fromhex("2f2000000f000000"),
            core1_prog=b"",
            shared_mem_init=[],
            interrupt_plan_raw=[],
            name="scenario",
            description="generated",
            tags=[
                "target:sfuzz_atomic",
                "target:sfuzz_fence",
                "event:amo_fire",
                "event:fence_drain",
                "event:load_replay",
            ],
        )

        ir = infer_seed_micro_ir(seed)

        self.assertGreaterEqual(ir.group_affinity["sfuzz_atomic"], 8)
        self.assertGreaterEqual(ir.group_affinity["sfuzz_fence"], 8)
        self.assertGreaterEqual(ir.group_affinity["sfuzz_lsq"], 3)
        self.assertIn("sfuzz_atomic", ir.target_trace)

    def test_available_mutation_operators_reflect_current_program_shape(self) -> None:
        empty = bytearray()
        self.assertEqual(
            available_mutation_operators(empty),
            ("bitflip_byte", "overwrite_byte", "insert_random_bytes"),
        )
        self.assertEqual(empty, bytearray())

        longer = bytearray(b"\x00" * 8)
        self.assertIn("delete_range", available_mutation_operators(longer))

    def test_operator_selection_pool_keeps_legacy_five_way_shape(self) -> None:
        self.assertEqual(
            mutation_operator_selection_pool(bytearray(b"\x00\x01")),
            (
                "bitflip_byte",
                "overwrite_byte",
                "insert_random_bytes",
                "insert_random_bytes",
                "insert_random_bytes",
            ),
        )
        self.assertEqual(
            mutation_operator_selection_pool(bytearray(b"\x00" * 8)),
            (
                "bitflip_byte",
                "overwrite_byte",
                "bitflip_word",
                "delete_range",
                "insert_random_bytes",
            ),
        )

    def test_mutation_initializes_empty_core0_with_smoke_program(self) -> None:
        core0 = bytearray()

        summary = mutate_core0_program(core0, random.Random(5), 1)

        self.assertEqual(summary.budget, 1)
        self.assertGreaterEqual(len(core0), len(DEFAULT_CORE0_PROG))

    def test_operator_guards_prevent_invalid_width_mutations(self) -> None:
        with self.assertRaises(ValueError):
            apply_sfuz_mutation_operator(bytearray(b"\x00\x01"), "bitflip_word", random.Random(1))

        with self.assertRaises(ValueError):
            apply_sfuz_mutation_operator(bytearray(DEFAULT_CORE0_PROG), "delete_range", random.Random(1))

    def test_mutate_core0_program_returns_budget_and_operator_trace(self) -> None:
        core0 = bytearray(DEFAULT_CORE0_PROG)
        summary = mutate_core0_program(core0, random.Random(7), 3)

        self.assertEqual(summary.budget, 3)
        self.assertEqual(len(summary.operators), 3)
        self.assertNotEqual(bytes(core0), DEFAULT_CORE0_PROG)
        self.assertEqual(summary.operator_trace, ";".join(summary.operators))
        self.assertEqual(summary.section_trace, "core0;core0;core0")

    def test_mutate_sfuz_default_preserves_non_core0_sections(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            parent = root / "parent.sfuz"
            output = root / "mutated.sfuz"
            write_sfuz_seed(
                parent,
                SfuzSeed(
                    core0_prog=DEFAULT_CORE0_PROG,
                    core1_prog=b"core1",
                    shared_mem_init=[(0x8000, b"shared")],
                    interrupt_plan_raw=[b"\x01" * 24],
                    name="seed-a",
                    description="fixture",
                    tags=["fixture"],
                ),
            )

            summary = mutate_sfuz(parent, output, random.Random(3), 2, semantic=False)
            mutated = read_sfuz_seed(output)

        self.assertEqual(summary.budget, 2)
        self.assertEqual(len(summary.operators), 2)
        self.assertNotEqual(mutated.core0_prog, DEFAULT_CORE0_PROG)
        self.assertEqual(mutated.core1_prog, b"core1")
        self.assertEqual(mutated.shared_mem_init, [(0x8000, b"shared")])
        self.assertEqual(mutated.interrupt_plan_raw, [b"\x01" * 24])
        self.assertIn("sfuzz-online-mutated", mutated.tags)

    def test_mutate_sfuz_can_target_core1_shared_and_interrupt_sections(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            parent = root / "parent.sfuz"
            output = root / "mutated.sfuz"
            write_sfuz_seed(
                parent,
                SfuzSeed(
                    core0_prog=DEFAULT_CORE0_PROG,
                    core1_prog=b"",
                    shared_mem_init=[],
                    interrupt_plan_raw=[],
                    name="seed-b",
                    description="fixture",
                    tags=["fixture"],
                ),
            )

            summary = mutate_sfuz(parent, output, random.Random(11), 8, "core1,shared,interrupt", semantic=False)
            mutated = read_sfuz_seed(output)

        self.assertEqual(summary.budget, 8)
        self.assertIn("core1", summary.section_trace)
        self.assertTrue({"shared", "interrupt"} & set(summary.sections))
        self.assertEqual(mutated.core0_prog, DEFAULT_CORE0_PROG)
        self.assertTrue(mutated.core1_prog or mutated.shared_mem_init or mutated.interrupt_plan_raw)
        for event in mutated.interrupt_plan_raw:
            self.assertEqual(len(event), 24)

    def test_mutate_sfuz_default_uses_semantic_scenario_operator(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            parent = root / "parent.sfuz"
            output = root / "mutated.sfuz"
            write_sfuz_seed(
                parent,
                SfuzSeed(
                    core0_prog=DEFAULT_CORE0_PROG,
                    core1_prog=b"",
                    shared_mem_init=[],
                    interrupt_plan_raw=[],
                    name="seed-semantic",
                    description="fixture",
                    tags=["fixture"],
                ),
            )

            summary = mutate_sfuz(
                parent,
                output,
                random.Random(2),
                3,
                focus_group="sfuzz_atomic",
                seed_ir_targets="sfuzz_atomic:8",
                mutation_index=7,
            )
            mutated = read_sfuz_seed(output)
            sidecar_seen = output.with_suffix(".scenario.json").is_file()

        self.assertEqual(summary.budget, 3)
        self.assertTrue(all(operator.startswith("semantic.") for operator in summary.operators))
        self.assertEqual(len(summary.operators), 1)
        self.assertTrue(summary.scenario_family)
        self.assertTrue(summary.expected_events)
        self.assertIn("sfuzz-scenario", mutated.tags)
        self.assertTrue(sidecar_seen)
        self.assertTrue(any(tag.startswith("target:sfuzz_") for tag in mutated.tags))

    def test_mutate_sfuz_can_avoid_stalled_semantic_operator(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            parent = root / "parent.sfuz"
            output = root / "mutated.sfuz"
            write_sfuz_seed(
                parent,
                SfuzSeed(
                    core0_prog=DEFAULT_CORE0_PROG,
                    core1_prog=b"",
                    shared_mem_init=[],
                    interrupt_plan_raw=[],
                    name="seed-semantic",
                    description="fixture",
                    tags=["fixture"],
                ),
            )

            summary = mutate_sfuz(
                parent,
                output,
                random.Random(0),
                1,
                focus_group="sfuzz_fence",
                stalled_operators=("insert_fence_before_after_amo",),
            )

        self.assertEqual(summary.operators, ("semantic.insert_fence_rw_rw",))

    def test_sfuzz_csv_exposes_semantic_operator_column(self) -> None:
        entry = CorpusEntry(
            1,
            Path("mut.sfuz"),
            "mut",
            "cat",
            energy=1,
            mutation_operators="byte.flip;semantic.insert_lrsc_pair",
        )

        self.assertIn("semantic_operator", SFUZZ_FIELDS)
        self.assertEqual(semantic_operator_name(entry), "insert_lrsc_pair")

    def test_infer_seed_semantic_fields_reads_scenario_tags(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scenario.sfuz"
            scenario = scenario_from_operator("insert_amo_sequence", variant=1, rng=random.Random(1))
            write_scenario_artifacts(path, scenario)

            operator_trace, section_trace, scheduler_family = infer_seed_semantic_fields(path)

        self.assertEqual(operator_trace, "semantic.insert_amo_sequence")
        self.assertEqual(section_trace, "scenario:amo_contention")
        self.assertEqual(scheduler_family, "initial:amo_contention")

    def test_normalize_mutation_sections_accepts_all_and_deduplicates(self) -> None:
        self.assertEqual(normalize_mutation_sections(None), ("core0",))
        self.assertEqual(normalize_mutation_sections("core0, core1,core0"), ("core0", "core1"))
        self.assertEqual(normalize_mutation_sections("all"), ("core0", "core1", "shared", "interrupt"))
        with self.assertRaises(ValueError):
            normalize_mutation_sections("core0,unknown")

    def test_plan_sections_for_focus_uses_microstructure_hints(self) -> None:
        self.assertEqual(
            plan_sections_for_focus("core0,shared,interrupt", "memory_event"),
            ("shared", "core0", "interrupt"),
        )
        self.assertEqual(
            plan_sections_for_focus("core0,shared,interrupt", "exception_event"),
            ("interrupt", "core0", "shared"),
        )
        self.assertEqual(
            plan_sections_for_focus("core0,shared", "", "memory_event:5;branch_event:3"),
            ("shared", "core0"),
        )


class SfuzzScenarioTests(unittest.TestCase):
    def test_generate_all_p0_scenario_families_as_sfuz(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for index, family in enumerate(SCENARIO_FAMILIES):
                scenario = generate_scenario(family, variant=index, rng=random.Random(index))
                output = root / f"{family}.sfuz"

                write_scenario_artifacts(output, scenario)
                seed = read_sfuz_seed(output)
                words = [
                    int.from_bytes(seed.core0_prog[i : i + 4], "little")
                    for i in range(0, len(seed.core0_prog), 4)
                ]

                self.assertGreaterEqual(len(seed.core0_prog), 8)
                self.assertIn(0x0005006B, words)
                self.assertNotIn(0x00100073, words)
                self.assertIn("sfuzz-scenario", seed.tags)
                self.assertIn(f"scenario:{family}", seed.tags)
                self.assertTrue(scenario.expected_micro_events)
                self.assertTrue(scenario.target_groups)
                self.assertTrue(output.with_suffix(".S").is_file())
                self.assertTrue(output.with_suffix(".scenario.json").is_file())

    def test_atomic_and_fence_scenarios_are_instruction_level_not_byte_flips(self) -> None:
        amo = scenario_from_operator("insert_amo_sequence", variant=3, rng=random.Random(3))
        fence = scenario_from_operator("insert_fence_before_after_amo", variant=4, rng=random.Random(4))
        amo_seed = seed_from_scenario(amo)
        fence_seed = seed_from_scenario(fence)

        self.assertIn("target:sfuzz_atomic", amo_seed.tags)
        self.assertIn("target:sfuzz_fence", fence_seed.tags)
        self.assertTrue(any(word & 0x7F == 0x2F for word in (int.from_bytes(amo_seed.core0_prog[i:i+4], "little") for i in range(0, len(amo_seed.core0_prog), 4))))
        self.assertTrue(any(word & 0x7F == 0x0F for word in (int.from_bytes(fence_seed.core0_prog[i:i+4], "little") for i in range(0, len(fence_seed.core0_prog), 4))))
        self.assertIn("amo_fire", amo.expected_micro_events)
        self.assertIn("fence_fire", fence.expected_micro_events)

    def test_scenarios_end_with_linknan_good_trap_not_plain_ebreak(self) -> None:
        scenario = generate_scenario("memory_alias", variant=0, rng=random.Random(0))
        seed = seed_from_scenario(scenario)
        words = [
            int.from_bytes(seed.core0_prog[i : i + 4], "little")
            for i in range(0, len(seed.core0_prog), 4)
        ]

        self.assertEqual(words[-2], 0x00000513)
        self.assertEqual(words[-1], 0x0005006B)
        self.assertNotEqual(words[-1], 0x00100073)

    def test_exception_scenario_has_bounded_handler_after_good_trap_path(self) -> None:
        scenario = scenario_from_operator("insert_exception_near_memory", variant=0, rng=random.Random(0))
        seed = seed_from_scenario(scenario)
        words = [
            int.from_bytes(seed.core0_prog[i : i + 4], "little")
            for i in range(0, len(seed.core0_prog), 4)
        ]

        self.assertIn(0x00000073, words)  # ecall
        self.assertIn(0x0005006B, words)
        self.assertEqual(words[-1], 0x30200073)  # mret
        self.assertLess(words.index(0x0005006B), len(words) - 1)

    def test_multicore_scenarios_are_marked_fallback_without_core1_handoff(self) -> None:
        scenario = scenario_from_operator("insert_multicore_pingpong", variant=1, rng=random.Random(1))
        seed = seed_from_scenario(scenario)

        self.assertTrue(scenario.requires_core1_handoff)
        self.assertFalse(scenario.core1_handoff_enabled)
        self.assertFalse(scenario.formal_multicore_result)
        self.assertGreater(len(seed.core1_prog), 0)
        self.assertIn("single-core-fallback", seed.tags)

    def test_long_runtime_profile_tags_stress_loop(self) -> None:
        scenario = scenario_from_operator(
            "insert_amo_sequence",
            variant=2,
            rng=random.Random(2),
            runtime_profile="long",
            target_min_wall_time_sec=60,
        )
        seed = seed_from_scenario(scenario)

        self.assertEqual(scenario.runtime_profile, "long")
        self.assertGreaterEqual(scenario.stress_iterations, 60 * 4096)
        self.assertIn("runtime_profile:long", seed.tags)
        self.assertIn("target_min_wall_time_sec:60", seed.tags)

    def test_long_multicore_profile_keeps_core1_running(self) -> None:
        scenario = scenario_from_operator(
            "insert_amo_sequence",
            variant=2,
            rng=random.Random(2),
            core1_handoff_enabled=True,
            runtime_profile="long",
            target_min_wall_time_sec=60,
        )
        seed = seed_from_scenario(scenario)
        core1_words = [
            int.from_bytes(seed.core1_prog[index : index + 4], "little")
            for index in range(0, len(seed.core1_prog), 4)
        ]

        self.assertGreaterEqual(core1_words.count(0x0330000F), 2)
        self.assertEqual(core1_words[-1], 0x0005006B)

    def test_semantic_operator_selection_uses_native_group_deficit(self) -> None:
        atomic_operator = choose_semantic_operator("sfuzz_atomic", rng=random.Random(0))
        fence_operator = choose_semantic_operator("sfuzz_fence", rng=random.Random(0))
        fallback_operator = choose_semantic_operator("", "sfuzz_lsq:5", rng=random.Random(0))

        self.assertIn(atomic_operator, {"insert_amo_sequence", "insert_lrsc_pair", "insert_fence_before_after_amo"})
        self.assertIn(fence_operator, {"insert_fence_rw_rw", "insert_fence_before_after_amo"})
        self.assertIn(fallback_operator, {"create_store_load_dependency", "create_load_use_dependency", "increase_replay_pressure"})

    def test_semantic_operator_selection_avoids_stalled_candidates_when_possible(self) -> None:
        operator = choose_semantic_operator(
            "sfuzz_fence",
            rng=random.Random(0),
            stalled_operators=("insert_fence_before_after_amo",),
        )

        self.assertEqual(operator, "insert_fence_rw_rw")

    def test_semantic_variants_change_instruction_pressure_depth(self) -> None:
        shallow = scenario_from_operator("increase_mshr_pressure", variant=0, rng=random.Random(0))
        deep = scenario_from_operator("increase_mshr_pressure", variant=4, rng=random.Random(0))

        self.assertGreater(len(deep.core_payload(0)), len(shallow.core_payload(0)))

    def test_generate_scenario_corpus_writes_multiple_families(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = generate_scenario_corpus(Path(tmp), count=5, rng_seed=9)

            self.assertEqual(len(paths), 5)
            self.assertEqual(len({read_sfuz_seed(path).name for path in paths}), 5)
            self.assertTrue(all(path.with_suffix(".scenario.json").is_file() for path in paths))


class SfuzzCoverageTests(unittest.TestCase):
    def test_coverage_delta_uses_byte_per_point_semantics(self) -> None:
        accumulated = bytearray()

        first = coverage_delta(b"\x00\x01\xff", accumulated)
        second = coverage_delta(b"\x00\x02\x80", accumulated)

        self.assertEqual(first, 2)
        self.assertEqual(second, 0)
        self.assertEqual(accumulated, bytearray(b"\x00\x01\x01"))
        self.assertEqual(accumulated_covered(accumulated), 2)

    def test_coverage_delta_handles_missing_bitmap_and_size_mismatch(self) -> None:
        accumulated = bytearray(b"\x00\x01")

        self.assertEqual(coverage_delta(None, accumulated), 0)
        with self.assertRaises(ValueError):
            coverage_delta(b"\x01", accumulated)

    def test_parse_coverage_group_snapshot_reads_firrtl_group_deficits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = Path(tmp) / "sfuzz_firrtl_coverage.json"
            summary.write_text(
                """
                {
                  "backend": "sfuzz_firrtl",
                  "groups": [
                    {"name": "all", "total": 8, "covered": 3},
                    {"name": "common", "total": 8, "covered": 3},
                    {"name": "memory_event", "total": 10, "covered": 4},
                    {"name": "branch_event", "total": 6, "covered": 6}
                  ]
                }
                """,
                encoding="utf-8",
            )

            snapshot = parse_coverage_group_snapshot(CoverageResult(coverage_source=str(summary)))

        self.assertEqual(snapshot.total["memory_event"], 10)
        self.assertEqual(snapshot.covered["memory_event"], 4)
        self.assertEqual(coverage_group_deficits(snapshot), {"memory_event": 6, "branch_event": 0})

    def test_sfuzz_native_request_is_not_wrapped_as_firrtl_common(self) -> None:
        self.assertEqual(normalize_firrtl_coverage_name("SFUZZ.native"), "SFUZZ.native")
        self.assertEqual(requested_firrtl_groups("SFUZZ.native"), {"sfuzz_native"})
        self.assertEqual(requested_firrtl_groups("FIRRTL.SFUZZ.native"), {"sfuzz_native"})
        self.assertEqual(requested_firrtl_groups("sfuzz_atomic"), {"sfuzz_atomic"})

    def test_parse_coverage_group_snapshot_reads_sfuzz_native_groups(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = Path(tmp) / "sfuzz_native_coverage.json"
            summary.write_text(
                """
                {
                  "backend": "sfuzz_firrtl",
                  "native_backend": "sfuzz_semantic_native_coverage",
                  "coverage_name": "SFUZZ.native",
                  "group": "sfuzz_native",
                  "groups": [
                    {"name": "sfuzz_native", "total": 32, "covered": 7},
                    {"name": "sfuzz_atomic", "total": 5, "covered": 1},
                    {"name": "sfuzz_fence", "total": 4, "covered": 0},
                    {"name": "sfuzz_lsq", "total": 8, "covered": 3}
                  ]
                }
                """,
                encoding="utf-8",
            )

            snapshot = parse_coverage_group_snapshot(CoverageResult(coverage_source=str(summary)))

        self.assertEqual(snapshot.total["sfuzz_atomic"], 5)
        self.assertEqual(snapshot.covered["sfuzz_lsq"], 3)
        self.assertEqual(coverage_group_deficits(snapshot)["sfuzz_fence"], 4)

    def test_coverage_group_delta_slices_native_bitmap_in_group_order(self) -> None:
        snapshot = parse_coverage_group_snapshot(CoverageResult())
        snapshot = type(snapshot)(
            covered={"sfuzz_atomic": 2, "sfuzz_fence": 1},
            total={"sfuzz_atomic": 4, "sfuzz_fence": 3},
            order=("sfuzz_atomic", "sfuzz_fence"),
        )
        accumulated: dict[str, bytearray] = {}

        first_new, first_acc = coverage_group_delta(b"\x01\x00\x01\x00\x00\x01\x00", accumulated, snapshot)
        second_new, second_acc = coverage_group_delta(b"\x01\x01\x01\x00\x00\x01\x01", accumulated, snapshot)

        self.assertEqual(first_new, {"sfuzz_atomic": 2, "sfuzz_fence": 1})
        self.assertEqual(first_acc, {"sfuzz_atomic": 2, "sfuzz_fence": 1})
        self.assertEqual(second_new, {"sfuzz_atomic": 1, "sfuzz_fence": 1})
        self.assertEqual(second_acc, {"sfuzz_atomic": 3, "sfuzz_fence": 2})

    def test_simv_no_diff_compile_detection_guards_trap_abi(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            comp = root / "simv" / "comp"
            comp.mkdir(parents=True)
            (comp / "vcs_cmd.sh").write_text("vcs -CFLAGS \"-DCONFIG_NO_DIFFTEST -DFIRRTL_COVER\"\n")

            self.assertTrue(simv_compiled_without_difftest(root))

            (comp / "vcs_cmd.sh").write_text("vcs -CFLAGS \"-DFIRRTL_COVER\"\n")

            self.assertFalse(simv_compiled_without_difftest(root))


class SfuzzSchedulerTests(unittest.TestCase):
    def test_select_weighted_parent_uses_energy_as_ticket_weight(self) -> None:
        corpus = [
            CorpusEntry(0, Path("a.sfuz"), "a", "cat", energy=1),
            CorpusEntry(1, Path("b.sfuz"), "b", "cat", energy=3),
        ]

        first = select_weighted_parent(corpus, FixedTicketRng(0))
        second = select_weighted_parent(corpus, FixedTicketRng(1))
        last = select_weighted_parent(corpus, FixedTicketRng(3))

        self.assertEqual(first.entry.corpus_id, 0)
        self.assertEqual(first.corpus_index, 0)
        self.assertEqual(first.weight, 1)
        self.assertEqual(first.total_weight, 4)
        self.assertEqual(second.entry.corpus_id, 1)
        self.assertEqual(last.entry.corpus_id, 1)

    def test_select_weighted_parent_clamps_bad_energy_to_one(self) -> None:
        corpus = [
            CorpusEntry(0, Path("a.sfuz"), "a", "cat", energy=0),
            CorpusEntry(1, Path("b.sfuz"), "b", "cat", energy=-9),
        ]

        selected = select_weighted_parent(corpus, FixedTicketRng(1))

        self.assertEqual(selected.entry.corpus_id, 1)
        self.assertEqual(selected.weight, 1)
        self.assertEqual(selected.total_weight, 2)

    def test_select_weighted_parent_scales_seed_ir_by_group_deficit(self) -> None:
        corpus = [
            CorpusEntry(0, Path("a.sfuz"), "a", "cat", energy=1, seed_ir_targets="branch_event:2"),
            CorpusEntry(1, Path("b.sfuz"), "b", "cat", energy=1, seed_ir_targets="memory_event:4"),
        ]
        deficits = {"branch_event": 1, "memory_event": 64}

        first_weight = scheduler_weight(corpus[0], deficits)
        second_weight = scheduler_weight(corpus[1], deficits)
        selected = select_weighted_parent(corpus, FixedTicketRng(first_weight), deficits)

        self.assertGreater(second_weight, first_weight)
        self.assertEqual(selected.entry.corpus_id, 1)
        self.assertEqual(selected.focus_group, "memory_event")
        self.assertEqual(selected.focus_deficit, 64)

    def test_select_weighted_parent_ignores_fully_covered_groups(self) -> None:
        entry = CorpusEntry(0, Path("a.sfuz"), "a", "cat", energy=1, seed_ir_targets="branch_event:9")

        self.assertEqual(scheduler_weight(entry, {"branch_event": 0}), 1)
        selected = select_weighted_parent([entry], FixedTicketRng(0), {"branch_event": 0})

        self.assertEqual(selected.focus_group, "")
        self.assertEqual(selected.focus_deficit, 0)

    def test_select_weighted_parent_requires_non_empty_corpus(self) -> None:
        with self.assertRaises(ValueError):
            select_weighted_parent([], random.Random(1))

    def test_bounded_energy_remains_coverage_delta_driven(self) -> None:
        self.assertEqual(bounded_energy(0, 2, 8), 2)
        self.assertEqual(bounded_energy(1, 2, 8), 3)
        self.assertEqual(bounded_energy(255, 2, 8), 8)

    def test_baseline_parent_round_robins_without_energy_weighting(self) -> None:
        corpus = [
            CorpusEntry(0, Path("a.sfuz"), "a", "cat", energy=100),
            CorpusEntry(1, Path("b.sfuz"), "b", "cat", energy=1),
        ]

        first = select_baseline_parent(corpus, 0)
        second = select_baseline_parent(corpus, 1)
        wrapped = select_baseline_parent(corpus, 2)

        self.assertEqual(first.entry.corpus_id, 0)
        self.assertEqual(second.entry.corpus_id, 1)
        self.assertEqual(wrapped.entry.corpus_id, 0)
        self.assertEqual(first.policy, BASELINE_SCHEDULER_POLICY)
        self.assertEqual(first.weight, 1)
        self.assertEqual(first.total_weight, 2)

    def test_select_parent_dispatches_baseline_and_weighted_policies(self) -> None:
        corpus = [
            CorpusEntry(0, Path("a.sfuz"), "a", "cat", energy=1),
            CorpusEntry(1, Path("b.sfuz"), "b", "cat", energy=3),
        ]

        baseline = select_parent(corpus, random.Random(1), "baseline-fifo", 1)
        weighted = select_parent(corpus, FixedTicketRng(3), "weighted-innovation", 0)

        self.assertEqual(baseline.entry.corpus_id, 1)
        self.assertEqual(baseline.policy, BASELINE_SCHEDULER_POLICY)
        self.assertEqual(weighted.entry.corpus_id, 1)
        with self.assertRaises(ValueError):
            select_parent(corpus, random.Random(1), "unknown", 0)

    def test_semantic_bandit_parent_keeps_hard_target_exploration(self) -> None:
        corpus = [
            CorpusEntry(0, Path("a.sfuz"), "a", "cat", energy=1, seed_ir_targets="sfuzz_dcache:8"),
            CorpusEntry(1, Path("b.sfuz"), "b", "cat", energy=1, seed_ir_targets="sfuzz_atomic:8"),
        ]
        runtime = SchedulerRuntime()
        deficits = {"sfuzz_dcache": 100, "sfuzz_atomic": 16}

        selected = select_semantic_bandit_parent(corpus, FixedTicketRng(0), deficits, runtime)

        self.assertEqual(selected.entry.corpus_id, 1)
        self.assertEqual(selected.policy, "semantic_bandit")
        self.assertEqual(selected.focus_group, "sfuzz_atomic")
        self.assertTrue(selected.bucket.startswith("hard-target:"))

    def test_hard_target_focus_can_disable_coherence_without_core1_handoff(self) -> None:
        runtime = SchedulerRuntime()
        deficits = {"sfuzz_coherence": 1000, "sfuzz_atomic": 8}

        focus, deficit = hard_target_focus_group(deficits, runtime, ("sfuzz_atomic", "sfuzz_fence"))

        self.assertEqual(focus, "sfuzz_atomic")
        self.assertEqual(deficit, 8)

    def test_runtime_feedback_tracks_operator_family_and_first_hit(self) -> None:
        entry = CorpusEntry(
            2,
            Path("mut.sfuz"),
            "mut",
            "cat",
            energy=1,
            mutation_operators="semantic.insert_amo_sequence",
            mutation_sections="scenario:amo_contention",
        )
        runtime = SchedulerRuntime()

        update_runtime_feedback(
            runtime,
            entry,
            campaign_exec=7,
            new_bits=5,
            group_new_bits={"sfuzz_atomic": 2, "sfuzz_lsq": 0},
        )
        self.assertEqual(entry.hard_target_hit_groups, "sfuzz_atomic")
        self.assertEqual(entry.hard_target_new_bits, 2)

        update_runtime_feedback(runtime, entry, campaign_exec=8, new_bits=0, group_new_bits={})

        self.assertEqual(runtime.operator_credit["insert_amo_sequence"], 5)
        self.assertEqual(runtime.operator_hard_target_credit["insert_amo_sequence"], 2)
        self.assertEqual(runtime.operator_stall["insert_amo_sequence"], 1)
        self.assertEqual(runtime.family_credit["amo_contention"], 5)
        self.assertEqual(runtime.family_hard_target_credit["amo_contention"], 2)
        self.assertEqual(runtime.hard_target_first_hit["sfuzz_atomic"], 7)
        self.assertEqual(entry.hard_target_new_bits, 0)
        self.assertEqual(entry.no_new_coverage_streak, 1)

    def test_retention_reason_prioritizes_bug_and_hard_target(self) -> None:
        from linknan.methods.sfuzz import retention_reason_for_run

        self.assertEqual(retention_reason_for_run("bug_triggered", 0, {}), (True, "bug_signature"))
        self.assertEqual(
            retention_reason_for_run("good_trap", 0, {"sfuzz_atomic": 1}),
            (True, "hard_target_hit:sfuzz_atomic"),
        )
        self.assertEqual(
            retention_reason_for_run("good_trap", 0, {"sfuzz_branch": 1}, "sfuzz_branch"),
            (True, "score_improvement:sfuzz_branch"),
        )
        self.assertEqual(retention_reason_for_run("good_trap", 3, {}), (True, "new_coverage"))
        self.assertEqual(retention_reason_for_run("good_trap", 0, {}), (False, "not_interesting"))

    def test_append_simv_arg_preserves_existing_args(self) -> None:
        self.assertEqual(append_simv_arg(None, "+sfuzz_enable_all_cores=1"), "+sfuzz_enable_all_cores=1")
        self.assertEqual(
            append_simv_arg("+foo=1", "+sfuzz_enable_all_cores=1"),
            "+foo=1 +sfuzz_enable_all_cores=1",
        )

    def test_core1_handoff_defaults_to_dual_core_build(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = Namespace(
                config=str(root / "missing.toml"),
                linknan_root=str(root / "LinkNan"),
                build_dir=root / "build",
                sim_dir=root / "sim",
                no_cycle_limit=True,
                cycles=None,
                enable_core1_handoff=True,
            )

            ctx = context_from_config(args)

        self.assertEqual(ctx.num_cores, "2")

    def test_core1_handoff_rejects_explicit_single_core_build(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = Namespace(
                config=str(root / "missing.toml"),
                linknan_root=str(root / "LinkNan"),
                build_dir=root / "build",
                sim_dir=root / "sim",
                no_cycle_limit=True,
                cycles=None,
                enable_core1_handoff=True,
            )

            with mock.patch.dict("os.environ", {"NUM_CORES": "1"}):
                with self.assertRaisesRegex(ValueError, "NUM_CORES>=2"):
                    context_from_config(args)

    def test_vcs_log_parser_records_core1_handoff_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_log = root / "run.log"
            assert_log = root / "assert.log"
            run_log.write_text(
                "SFUZZ_CORE_PAYLOAD: name=core0 paddr=0x80000000 size=4\n"
                "SFUZZ_CORE_PAYLOAD: name=core1 paddr=0x81000000 size=8\n"
                "SFUZZ_CORE1_HANDOFF: staged=1 entry=0x81000000 size=8 executed=0 reason=secondary_slot_only\n"
                "SFUZZ_CORE_EXECUTED: core=1 instrCnt=16 pc=0x8100001c\n",
                encoding="utf-8",
            )
            assert_log.write_text("", encoding="utf-8")

            info = scan_vcs_logs(run_log, assert_log, None)

        self.assertTrue(info.sfuzz_core0_staged)
        self.assertTrue(info.sfuzz_core1_staged)
        self.assertTrue(info.sfuzz_core1_executed)
        self.assertEqual(info.sfuzz_core1_entry, "0x81000000")
        self.assertEqual(info.sfuzz_core1_payload_size, 8)
        self.assertEqual(info.sfuzz_core1_handoff_reason, "core1_instr_count")

    def test_select_parent_dispatches_semantic_bandit_policy(self) -> None:
        corpus = [
            CorpusEntry(0, Path("a.sfuz"), "a", "cat", energy=1, seed_ir_targets="sfuzz_atomic:8"),
            CorpusEntry(1, Path("b.sfuz"), "b", "cat", energy=1, seed_ir_targets="sfuzz_lsq:8"),
        ]
        selected = select_parent(
            corpus,
            FixedTicketRng(0),
            "semantic-bandit",
            0,
            {"sfuzz_atomic": 10, "sfuzz_lsq": 1},
            SchedulerRuntime(),
        )

        self.assertEqual(selected.policy, "semantic_bandit")


if __name__ == "__main__":
    unittest.main()
