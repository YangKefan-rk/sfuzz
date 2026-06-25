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
    merge_worker_csvs,
    per_worker_budget,
    prepare_isolated_build_dirs,
    write_seed_shards,
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

    def test_t2_campaign_splits_total_budget_across_workers(self) -> None:
        self.assertEqual(per_worker_budget(1000, 4), 250)
        self.assertEqual(per_worker_budget(1001, 4), 251)
        self.assertEqual(per_worker_budget(1, 4), 1)
        self.assertEqual(per_worker_budget(1000, 0), 1000)

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
                timeout_sec=600,
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
                workers_per_fuzzer=1,
                isolated_sim_dirs=True,
            )

            commands = campaign_commands(args, paths, sfuzz_list, workload_list)

        self.assertEqual([item["method"] for item in commands], ["sfuzz", "rfuzz", "directfuzz", "surgefuzz"])
        for item in commands:
            command_text = " ".join(item["command"])
            self.assertIn("--no-cycle-limit", command_text)
            self.assertIn("--timeout-sec 600", command_text)
            self.assertIn("--build-dir", command_text)
            self.assertIn("--sim-dir", command_text)
            self.assertNotIn("--cycles=", command_text)
            self.assertNotIn("--skip-build", command_text)
        self.assertIn("--campaign-runs 1000", " ".join(commands[0]["command"]))
        for item in commands:
            self.assertEqual(item["env"], {"NUM_CORES": "2"})
        self.assertIn("--rfuzz-rounds 1000", " ".join(commands[1]["command"]))
        self.assertIn("--require-paper-native", " ".join(commands[2]["command"]))
        self.assertIn("--require-paper-native", " ".join(commands[3]["command"]))

    def test_t2_campaign_shards_each_fuzzer_worker(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata = root / "direct.csv"
            surge_manifest = root / "surge.toml"
            manifest = root / "manifest.csv"
            metadata.write_text("instance_name,coverage_signal_name,width,distance\ntarget,cov,1,0\n", encoding="utf-8")
            surge_manifest.write_text("[[targets]]\nid='t'\n", encoding="utf-8")
            rows = ["testcase_id,source,category,input_path,input_format,file_size,sfuzz_seed_path,rfuzz_workload_path"]
            for index in range(4):
                seed = root / f"seed{index}.sfuz"
                workload = root / f"seed{index}.bin"
                seed.write_bytes(b"SFUZ")
                workload.write_bytes(b"\x73\x00\x10\x00")
                rows.append(f"tc{index},unit,ISA,{workload},bin,4,{seed},{workload}")
            manifest.write_text("\n".join(rows) + "\n", encoding="utf-8")
            testcases = load_testcases(manifest, limit=4)
            paths = CampaignPaths.create(root / "campaign")
            sfuzz_lists, workload_lists = write_seed_shards(paths, testcases, workers=2)
            args = SimpleNamespace(
                config=root / "sfuzz.toml",
                linknan_root=root / "LinkNan",
                timeout_sec=600,
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
                workers_per_fuzzer=2,
                isolated_sim_dirs=True,
            )

            commands = campaign_commands(args, paths, sfuzz_lists, workload_lists)

        self.assertEqual(len(commands), 8)
        self.assertEqual([item["worker_id"] for item in commands[:4]], [0, 0, 0, 0])
        self.assertEqual([item["worker_id"] for item in commands[4:]], [1, 1, 1, 1])
        for item in commands:
            command_text = " ".join(item["command"])
            self.assertIn("workers/worker-", command_text)
            self.assertIn("--timeout-sec 600", command_text)
            self.assertNotIn("--worker-id", command_text)
            self.assertEqual(item["env"], {"NUM_CORES": "2"})
        self.assertIn("--campaign-runs 500", " ".join(commands[0]["command"]))
        self.assertIn("--rfuzz-rounds 500", " ".join(commands[1]["command"]))
        self.assertIn("--formal-campaign-total-execs 1000", " ".join(commands[1]["command"]))
        self.assertIn("--max-execs 500", " ".join(commands[2]["command"]))
        self.assertIn("--mutations 500", " ".join(commands[2]["command"]))
        self.assertIn("--formal-campaign-total-execs 1000", " ".join(commands[2]["command"]))
        self.assertIn("--max-execs 500", " ".join(commands[3]["command"]))
        self.assertIn("--mutations 500", " ".join(commands[3]["command"]))
        self.assertIn("--formal-campaign-total-execs 1000", " ".join(commands[3]["command"]))

    def test_t2_campaign_merges_worker_csvs(self) -> None:
        import csv
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            worker0 = root / "results" / "sfuzz" / "workers" / "worker-000" / "results.csv"
            worker1 = root / "results" / "sfuzz" / "workers" / "worker-001" / "results.csv"
            output = root / "results" / "sfuzz" / "results.csv"
            worker0.parent.mkdir(parents=True)
            worker1.parent.mkdir(parents=True)
            output.parent.mkdir(parents=True, exist_ok=True)
            header = "exec_index,mutation_kind,accumulated_covered_bits,common_coverage_total\n"
            worker0.write_text(header + "0,semantic,3,10\n", encoding="utf-8")
            worker1.write_text(header + "0,semantic,5,10\n", encoding="utf-8")

            merge_worker_csvs("sfuzz", [worker0, worker1], output)

            with output.open(newline="", encoding="utf-8") as input_file:
                rows = list(csv.DictReader(input_file))

        self.assertEqual([row["worker_id"] for row in rows], ["000", "001"])
        self.assertEqual([row["accumulated_covered_bits"] for row in rows], ["3", "5"])

    def test_prepare_isolated_build_dirs_copies_rtl_per_worker(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            linknan = root / "LinkNan"
            rtl_cover = linknan / "build" / "rtl" / "verification" / "cover"
            generated = linknan / "build" / "generated-src"
            scripts = linknan / "scripts" / "linknan"
            rtl_cover.mkdir(parents=True)
            generated.mkdir(parents=True)
            scripts.mkdir(parents=True)
            (linknan / "build" / "rtl" / "SimTop.sv").write_text("module SimTop; endmodule\n", encoding="utf-8")
            (rtl_cover / "old.sv").write_text("module old; endmodule\n", encoding="utf-8")
            (generated / "soc.lua").write_text("return {}\n", encoding="utf-8")
            generator = scripts / "sfuzz_firrtl_cov.py"
            generator.write_text(
                "#!/usr/bin/env python3\n"
                "from pathlib import Path\n"
                "import sys\n"
                "rtl = Path(sys.argv[1])\n"
                "out = Path(sys.argv[sys.argv.index('--generated-src-dir') + 1])\n"
                "out.mkdir(parents=True, exist_ok=True)\n"
                "(out / 'firrtl-cover.h').write_text('h')\n"
                "(out / 'firrtl-cover.cpp').write_text('cpp')\n"
                "(out / 'sfuzz_firrtl_cover.json').write_text('{\\\"backend\\\":\\\"sfuzz_firrtl_sv_bind\\\",\\\"enabled_groups\\\":[\\\"sfuzz_native\\\"]}')\n"
                "cover = rtl / 'verification' / 'cover'\n"
                "cover.mkdir(parents=True, exist_ok=True)\n"
                "(cover / 'sfuzz_firrtl_cover_bind.sv').write_text('bind')\n",
                encoding="utf-8",
            )
            generator.chmod(0o755)
            paths = CampaignPaths.create(root / "campaign")
            args = SimpleNamespace(
                isolated_sim_dirs=True,
                build_chisel=False,
                linknan_root=linknan,
            )
            commands = [
                {
                    "method": "sfuzz",
                    "coverage_name": "SFUZZ.native",
                    "command": ["python3", "run.py", "sfuzz", "--build-dir", str(paths.results / "sfuzz" / "workers" / "worker-000" / "linknan-build")],
                },
                {
                    "method": "sfuzz",
                    "coverage_name": "SFUZZ.native",
                    "command": ["python3", "run.py", "sfuzz", "--build-dir", str(paths.results / "sfuzz" / "workers" / "worker-001" / "linknan-build")],
                },
            ]

            prepare_isolated_build_dirs(args, paths, commands)

            build0 = paths.results / "sfuzz" / "workers" / "worker-000" / "linknan-build"
            build1 = paths.results / "sfuzz" / "workers" / "worker-001" / "linknan-build"
            self.assertTrue((build0 / "rtl" / "SimTop.sv").is_file())
            self.assertTrue((build1 / "rtl" / "SimTop.sv").is_file())
            self.assertTrue((build0 / "generated-src" / "firrtl-cover.h").is_file())
            self.assertTrue((build1 / "generated-src" / "firrtl-cover.cpp").is_file())
            self.assertTrue((build0 / "rtl" / "verification" / "cover" / "sfuzz_firrtl_cover_bind.sv").is_file())
            self.assertTrue((build1 / "rtl" / "verification" / "cover" / "sfuzz_firrtl_cover_bind.sv").is_file())
            (build1 / "generated-src" / "sfuzz_firrtl_cover.json").write_text("worker1", encoding="utf-8")
            (build1 / "generated-src" / "firrtl-cover.cpp").write_text("worker1", encoding="utf-8")
            self.assertNotEqual((build0 / "generated-src" / "sfuzz_firrtl_cover.json").read_text(encoding="utf-8"), "worker1")
            self.assertEqual((build0 / "generated-src" / "firrtl-cover.cpp").read_text(encoding="utf-8"), "cpp")


if __name__ == "__main__":
    unittest.main()
