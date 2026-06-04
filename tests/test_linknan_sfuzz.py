from __future__ import annotations

import random
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from linknan.methods.sfuzz import (  # noqa: E402
    BASELINE_SCHEDULER_POLICY,
    DEFAULT_CORE0_PROG,
    CorpusEntry,
    apply_sfuz_mutation_operator,
    available_mutation_operators,
    bounded_energy,
    coverage_delta,
    accumulated_covered,
    coverage_group_deficits,
    mutate_core0_program,
    mutate_sfuz,
    mutation_operator_selection_pool,
    normalize_mutation_sections,
    parse_coverage_group_snapshot,
    plan_sections_for_focus,
    select_baseline_parent,
    select_parent,
    select_weighted_parent,
    scheduler_weight,
)
from linknan.seeds import SfuzSeed, infer_seed_micro_ir, read_sfuz_seed, write_sfuz_seed  # noqa: E402
from linknan.vcs import CoverageResult  # noqa: E402


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

            summary = mutate_sfuz(parent, output, random.Random(3), 2)
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

            summary = mutate_sfuz(parent, output, random.Random(11), 8, "core1,shared,interrupt")
            mutated = read_sfuz_seed(output)

        self.assertEqual(summary.budget, 8)
        self.assertIn("core1", summary.section_trace)
        self.assertTrue({"shared", "interrupt"} & set(summary.sections))
        self.assertEqual(mutated.core0_prog, DEFAULT_CORE0_PROG)
        self.assertTrue(mutated.core1_prog or mutated.shared_mem_init or mutated.interrupt_plan_raw)
        for event in mutated.interrupt_plan_raw:
            self.assertEqual(len(event), 24)

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


if __name__ == "__main__":
    unittest.main()
