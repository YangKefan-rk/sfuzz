from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from linknan.methods.directfuzz import directfuzz_mutation_limit  # noqa: E402
from linknan.methods.surgefuzz import surgefuzz_mutation_limit  # noqa: E402


class FormalRunnerBudgetTests(unittest.TestCase):
    def test_directfuzz_max_execs_drives_remaining_mutation_budget(self) -> None:
        self.assertEqual(directfuzz_mutation_limit(1000, 17, 8), 983)
        self.assertEqual(directfuzz_mutation_limit(1000, 1000, 8), 0)
        self.assertEqual(directfuzz_mutation_limit(0, 17, 8), 8)

    def test_surgefuzz_max_execs_drives_remaining_mutation_budget(self) -> None:
        self.assertEqual(surgefuzz_mutation_limit(1000, 3, 8), 997)
        self.assertEqual(surgefuzz_mutation_limit(1000, 1001, 8), 0)
        self.assertEqual(surgefuzz_mutation_limit(0, 3, 8), 8)


if __name__ == "__main__":
    unittest.main()
