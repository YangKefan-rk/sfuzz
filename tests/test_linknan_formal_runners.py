from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from linknan.methods.directfuzz import directfuzz_mutation_limit  # noqa: E402
from linknan.methods.surgefuzz import surgefuzz_mutation_limit  # noqa: E402
from linknan.t2_four_fuzzer_campaign import (  # noqa: E402
    CampaignPaths,
    campaign_commands,
    load_testcases,
    write_seed_lists,
)


class FormalRunnerBudgetTests(unittest.TestCase):
    def test_directfuzz_max_execs_drives_remaining_mutation_budget(self) -> None:
        self.assertEqual(directfuzz_mutation_limit(1000, 17, 8), 983)
        self.assertEqual(directfuzz_mutation_limit(1000, 1000, 8), 0)
        self.assertEqual(directfuzz_mutation_limit(0, 17, 8), 8)

    def test_surgefuzz_max_execs_drives_remaining_mutation_budget(self) -> None:
        self.assertEqual(surgefuzz_mutation_limit(1000, 3, 8), 997)
        self.assertEqual(surgefuzz_mutation_limit(1000, 1001, 8), 0)
        self.assertEqual(surgefuzz_mutation_limit(0, 3, 8), 8)

    def test_t2_campaign_prepare_builds_formal_four_fuzzer_commands(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed = root / "seed.sfuz"
            workload = root / "seed.bin"
            metadata = root / "direct.csv"
            surge_manifest = root / "surge.toml"
            manifest = root / "manifest.csv"
            seed.write_bytes(b"SFUZ")
            workload.write_bytes(b"\x73\x00\x10\x00")
            metadata.write_text("instance_name,coverage_signal_name,width,distance\ntarget,cov,1,0\n", encoding="utf-8")
            surge_manifest.write_text("[[targets]]\nid='t'\n", encoding="utf-8")
            manifest.write_text(
                "testcase_id,source,category,input_path,input_format,file_size,sfuzz_seed_path,rfuzz_workload_path\n"
                f"tc0,unit,ISA,{workload},bin,4,{seed},{workload}\n",
                encoding="utf-8",
            )
            testcases = load_testcases(manifest, limit=1)
            paths = CampaignPaths.create(root / "campaign")
            sfuzz_list, workload_list, _selected = write_seed_lists(paths, testcases)
            args = SimpleNamespace(
                config=root / "sfuzz.toml",
                linknan_root=root / "LinkNan",
                timeout_sec=120,
                build_mode="auto",
                build_chisel=False,
                build_timeout_sec=3600,
                simv_args="",
                exec_budget=1000,
                rng_seed=20260605,
                target_min_wall_time_sec=60,
                sfuzz_scheduler="semantic-bandit",
                direct_metadata=metadata,
                direct_target_instance="target",
                surge_target_manifest=surge_manifest,
                surge_target="t",
                surge_initial_seed_count=1,
                sfuzz_num_cores=2,
            )

            commands = campaign_commands(args, paths, sfuzz_list, workload_list)

        self.assertEqual([item["method"] for item in commands], ["sfuzz", "rfuzz", "directfuzz", "surgefuzz"])
        for item in commands:
            command_text = " ".join(item["command"])
            self.assertIn("--no-cycle-limit", command_text)
            self.assertIn("--timeout-sec 120", command_text)
            self.assertNotIn("--cycles=", command_text)
            self.assertNotIn("--skip-build", command_text)
        self.assertIn("--campaign-runs 1000", " ".join(commands[0]["command"]))
        self.assertEqual(commands[0]["env"], {"NUM_CORES": "2"})
        self.assertIn("--rfuzz-rounds 1000", " ".join(commands[1]["command"]))
        self.assertIn("--require-paper-native", " ".join(commands[2]["command"]))
        self.assertIn("--require-paper-native", " ".join(commands[3]["command"]))


if __name__ == "__main__":
    unittest.main()
