from __future__ import annotations

import random
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from linknan.methods.sfuzz import (  # noqa: E402
    DEFAULT_CORE0_PROG,
    CorpusEntry,
    apply_sfuz_mutation_operator,
    available_mutation_operators,
    bounded_energy,
    mutate_core0_program,
    mutate_sfuz,
    mutation_operator_selection_pool,
    select_weighted_parent,
)
from linknan.seeds import SfuzSeed, read_sfuz_seed, write_sfuz_seed  # noqa: E402


class FixedTicketRng:
    def __init__(self, ticket: int) -> None:
        self.ticket = ticket

    def randrange(self, stop: int) -> int:
        if not 0 <= self.ticket < stop:
            raise AssertionError(f"ticket {self.ticket} outside randrange({stop})")
        return self.ticket


class SfuzzMutationTests(unittest.TestCase):
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

    def test_mutate_sfuz_preserves_non_core0_sections(self) -> None:
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

    def test_select_weighted_parent_requires_non_empty_corpus(self) -> None:
        with self.assertRaises(ValueError):
            select_weighted_parent([], random.Random(1))

    def test_bounded_energy_remains_coverage_delta_driven(self) -> None:
        self.assertEqual(bounded_energy(0, 2, 8), 2)
        self.assertEqual(bounded_energy(1, 2, 8), 3)
        self.assertEqual(bounded_energy(255, 2, 8), 8)


if __name__ == "__main__":
    unittest.main()
