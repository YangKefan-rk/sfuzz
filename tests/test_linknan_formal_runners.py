from __future__ import annotations

import csv
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from linknan.methods.directfuzz import (  # noqa: E402
    CorpusEntry,
    DirectFuzzQueue,
    directfuzz_mutation_limit,
    directfuzz_power,
    run_directfuzz,
)
from linknan.methods.surgefuzz import surgefuzz_mutation_limit  # noqa: E402
from linknan.t2_four_fuzzer_campaign import (  # noqa: E402
    CampaignPaths,
    DEFAULT_BUILD_TIMEOUT_SEC,
    campaign_commands,
    load_testcases,
    merge_worker_csvs,
    per_worker_budget,
    prepare_isolated_build_dirs,
    write_seed_shards,
    write_seed_lists,
)


def _entry(corpus_id: int, *, energy: float, target: bool, progress: bool) -> CorpusEntry:
    feedback = {
        "energy": energy,
        "target_covered_bits": 4 if target else 0,
        "target_progress": progress,
    }
    return CorpusEntry(corpus_id, Path(f"/tmp/seed-{corpus_id}.bin"), feedback)


class DirectFuzzPowerScheduleTests(unittest.TestCase):
    def test_power_maps_energy_to_child_count(self) -> None:
        # energy (distance-derived, higher == closer) -> children = round(e)+1, clamped 1..64.
        self.assertEqual(directfuzz_power({"energy": 0.0}, False), 1)
        self.assertEqual(directfuzz_power({"energy": 24.0}, False), 25)
        self.assertEqual(directfuzz_power({"energy": 1000.0}, False), 64)

    def test_power_defaults_to_single_child(self) -> None:
        self.assertEqual(directfuzz_power({"energy": 7.0}, True), 1)  # escape selection
        self.assertEqual(directfuzz_power({"energy": ""}, False), 1)
        self.assertEqual(directfuzz_power({}, False), 1)


class DirectFuzzQueuePersistenceTests(unittest.TestCase):
    def test_queue_is_persistent_round_robin(self) -> None:
        queue = DirectFuzzQueue(escape_interval=0)
        a = _entry(0, energy=1.0, target=False, progress=False)
        b = _entry(1, energy=2.0, target=False, progress=False)
        queue.push(a)
        queue.push(b)

        picked = [queue.next().entry.corpus_id for _ in range(4)]
        self.assertEqual(picked, [0, 1, 0, 1])  # cycles, never consumed
        self.assertTrue(bool(queue))  # corpus persists across scheduling

    def test_target_entries_take_priority(self) -> None:
        queue = DirectFuzzQueue(escape_interval=0)
        queue.push(_entry(0, energy=1.0, target=False, progress=False))
        queue.push(_entry(1, energy=20.0, target=True, progress=False))
        scheduled = queue.next()
        self.assertEqual(scheduled.queue_name, "target")
        self.assertEqual(scheduled.entry.corpus_id, 1)

    def test_escape_fires_periodically(self) -> None:
        queue = DirectFuzzQueue(escape_interval=3)
        queue.push(_entry(0, energy=20.0, target=True, progress=False))
        queue.push(_entry(1, energy=1.0, target=False, progress=False))

        names = [queue.next().queue_name for _ in range(7)]
        # target stalls for escape_interval picks, then a regular-escape fires,
        # and the cycle repeats deterministically.
        self.assertEqual(
            names,
            ["target", "target", "target", "regular-escape", "target", "target", "target"],
        )

    def test_escape_uses_default_energy(self) -> None:
        queue = DirectFuzzQueue(escape_interval=1)
        queue.push(_entry(0, energy=20.0, target=True, progress=False))
        queue.push(_entry(1, energy=1.0, target=False, progress=False))
        queue.next()  # target, bumps stall counter to 1
        escape = queue.next()
        self.assertEqual(escape.queue_name, "regular-escape")
        self.assertTrue(escape.use_default_energy)


class DirectFuzzBudgetExhaustionTests(unittest.TestCase):
    """Regression guard: the persistent corpus must consume the full exec budget.

    Before the persistent-queue fix the destructive queue drained once mutations
    stopped finding new coverage, so campaigns stopped far short of --max-execs.
    """

    def _run(self, tmp: Path, *, max_execs: int, seeds: int) -> list[dict[str, str]]:
        from linknan.vcs import CommandResult, CoverageResult, VcsLogInfo

        work = tmp / "work"
        work.mkdir(parents=True, exist_ok=True)
        metadata = tmp / "direct.csv"
        metadata.write_text(
            "instance_name,coverage_signal_name,width,distance\n"
            "SimTop.target,cov_target,8,0\n"
            "SimTop.near,cov_near,8,1\n"
            "SimTop.far,cov_far,8,3\n",
            encoding="utf-8",
        )
        seed_paths = []
        for i in range(seeds):
            p = tmp / f"seed-{i}.bin"
            p.write_bytes(b"\x73\x00\x10\x00" + bytes([i, i + 7, i + 13]))
            seed_paths.append(str(p))

        out_csv = tmp / "results.csv"
        args = SimpleNamespace(
            work_dir=work,
            firrtl_cov=None,
            require_paper_native=False,
            seed=seed_paths,
            seed_list=None,
            seed_dir=None,
            limit=0,
            metadata=metadata,
            target_instance="SimTop.target",
            coverage_backend="dev-mock",
            native_coverage=None,
            native_coverage_source="dev-generated",
            native_coverage_pattern=None,
            metadata_source="dev-generated",
            max_execs=max_execs,
            mutations=8,
            formal_campaign_total_execs=0,
            escape_interval=10,
            rng_seed=1234,
            case_prefix="directfuzz",
            cov=False,
            simv_args=None,
            timeout_sec=600,
            output_csv=out_csv,
            output_json=tmp / "results.json",
        )
        ctx = SimpleNamespace(cycles=None, sim_dir=tmp / "sim")

        def fake_run_vcs_seed(**kwargs):
            runs_dir = kwargs["runs_dir"]
            case_dir = runs_dir / kwargs["case_name"]
            case_dir.mkdir(parents=True, exist_ok=True)
            run_log = case_dir / "run.log"
            assert_log = case_dir / "assert.log"
            run_log.touch()
            assert_log.touch()
            result = CommandResult(
                command=[],
                returncode=0,
                command_log_path=str(case_dir / "cmd.log"),
                wall_time_sec=0.01,
                timed_out=False,
            )
            return result, case_dir, run_log, assert_log

        module = "linknan.methods.directfuzz"
        with mock.patch(f"{module}.build_simv_if_needed"), \
            mock.patch(f"{module}.run_vcs_seed", side_effect=fake_run_vcs_seed), \
            mock.patch(f"{module}.scan_vcs_logs", return_value=VcsLogInfo()), \
            mock.patch(f"{module}.collect_vcs_coverage", return_value=CoverageResult()), \
            mock.patch(f"{module}.classify_infrastructure_error", return_value=""):
            rc = run_directfuzz(args, ctx)
        self.assertEqual(rc, 0)
        with out_csv.open(encoding="utf-8") as handle:
            return list(csv.DictReader(handle))

    def test_campaign_exhausts_exec_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rows = self._run(Path(tmp), max_execs=24, seeds=3)
        # The whole point: budget is consumed instead of draining early.
        self.assertEqual(len(rows), 24)
        initial = [r for r in rows if r["scheduler_queue"] == "initial"]
        self.assertEqual(len(initial), 3)
        # 24 execs from only 3 seeds proves the corpus is cycled, not consumed.
        mutations = [r for r in rows if r["scheduler_queue"] != "initial"]
        self.assertEqual(len(mutations), 21)


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
                build_timeout_sec=DEFAULT_BUILD_TIMEOUT_SEC,
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
            self.assertIn(f"--build-timeout-sec {DEFAULT_BUILD_TIMEOUT_SEC}", command_text)
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
                build_timeout_sec=DEFAULT_BUILD_TIMEOUT_SEC,
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
            self.assertIn(f"--build-timeout-sec {DEFAULT_BUILD_TIMEOUT_SEC}", command_text)
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
