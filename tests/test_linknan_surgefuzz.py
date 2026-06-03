from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from linknan.methods.surgefuzz import (  # noqa: E402
    Feedback,
    RotationState,
    append_row,
    load_rotation_targets,
    load_surge_trace,
    parse_annotation,
    score_series,
    write_instrumentation_target_config,
)
from linknan.surgefuzz_ancestors import AncestorCandidate  # noqa: E402
from linknan.surgefuzz_profile import write_nmi_report  # noqa: E402


class SurgeFuzzTraceTests(unittest.TestCase):
    def test_load_surge_trace_filters_indexed_multi_target_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            trace = Path(tmp) / "surgefuzz_trace.csv"
            trace.write_text(
                "cycle,target_index,target_id,coverage_target,dependent_0,dependent_1\n"
                "0,0,miss,0,1,2\n"
                "1,1,replay,1,3,4\n"
                "2,0,miss,1,5,6\n",
                encoding="utf-8",
            )

            values, dependents = load_surge_trace(trace, "coverage_target", target_index=0, target_id="miss")

        self.assertEqual(values, [0, 1])
        self.assertEqual(dependents, [(1, 2), (5, 6)])

    def test_score_series_keeps_surge_freq_semantics(self) -> None:
        self.assertEqual(score_series(*parse_annotation("SURGE_FREQ=1"), [0, 1, 1, 0], window=3), [0, 1, 2, 2])

    def test_nmi_report_uses_paired_profile_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp) / "profile.csv"
            report = Path(tmp) / "nmi.csv"
            profile.write_text(
                "cycle,coverage_target,a,b\n"
                "0,0,0,\n"
                "1,1,,1\n"
                "2,1,1,1\n"
                "3,,1,0\n",
                encoding="utf-8",
            )
            candidates = [
                AncestorCandidate("a", 1, "wire", 1, 0, True, "test"),
                AncestorCandidate("b", 1, "wire", 1, 0, True, "test"),
            ]

            write_nmi_report(report, candidates, profile, ["a"])
            rows = report.read_text(encoding="utf-8").splitlines()

        self.assertIn("a,1,1,0,1,1,2,", rows[1])
        self.assertIn("b,1,1,0,1,0,2,", rows[2])


class SurgeFuzzRotationTests(unittest.TestCase):
    def test_rotation_manifest_can_select_distance_only_for_without_mi_ablation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "rotation.json"
            manifest.write_text(
                json.dumps(
                    {
                        "targets": [
                            {
                                "id": "t0",
                                "category": "miss",
                                "module": "MemBlock",
                                "instance": "SimTop.soc.cc_0.tile.core.memBlock",
                                "signal": "target_sig",
                                "annotation": "SURGE_FREQ=1",
                                "ancestor_selector": "distance-nmi",
                                "selected_ancestors": ["mi_a"],
                                "mi_selected_ancestors": ["mi_a"],
                                "distance_selected_ancestors": ["distance_a", "distance_b"],
                                "mi_pruning_applied": True,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            targets = load_rotation_targets(manifest, disable_mi=True)
            out = Path(tmp) / "instrument.json"
            write_instrumentation_target_config(out, targets, disable_mi=True)
            payload = json.loads(out.read_text(encoding="utf-8"))

        self.assertEqual(targets[0].selected_ancestors, ("distance_a", "distance_b"))
        self.assertEqual(targets[0].ancestor_selector, "distance")
        self.assertFalse(targets[0].mi_pruning_applied)
        self.assertEqual(payload["targets"][0]["selected_ancestors"], ["distance_a", "distance_b"])
        self.assertEqual(payload["ablation"]["disable_mi"], True)

    def test_rotation_scheduler_round_robin_and_fixed_budget(self) -> None:
        targets = load_rotation_targets(
            self._manifest(
                [
                    ("t0", "a0"),
                    ("t1", "a1"),
                ]
            )
        )

        rr = RotationState(targets, "round-robin", budget_per_target=4, stall_threshold=3)
        fixed = RotationState(targets, "fixed-budget", budget_per_target=2, stall_threshold=3)

        self.assertEqual([rr.choose(i)[1].id for i in range(4)], ["t0", "t1", "t0", "t1"])
        self.assertEqual([fixed.choose(i)[1].id for i in range(5)], ["t0", "t0", "t1", "t1", "t0"])

    def test_append_row_marks_rotation_as_extension_not_paper_faithful(self) -> None:
        targets = load_rotation_targets(self._manifest([("t0", "a0")]))
        args = SimpleNamespace(
            input_mode="artifact-program",
            rotation_mode="round-robin",
            annotation_type="SURGE_FREQ=1",
            target_signal_or_group="target_sig",
            ancestor_selector="distance-nmi",
            ancestor_profile="profile.csv",
            score_column="coverage_target",
            disable_mi=False,
            disable_power_scheduling=False,
        )
        result = SimpleNamespace(wall_time_sec=0.1, returncode=0, command_log_path="cmd.log", timed_out=False)
        info = SimpleNamespace(
            cycles=None,
            max_cycle_exceeded=False,
            vcs_report_seen=True,
            sfuz_expansion_seen=False,
            good_trap_seen=True,
            bug_triggered=False,
            bug_reasons=[],
            vcs_cpu_time_sec=None,
            vcs_sim_time_ps=None,
        )
        coverage = SimpleNamespace(
            coverage_name="sfuzz_firrtl.surgefuzz_trace",
            coverage_value="50",
            coverage_source="cov.json",
            coverage_status="ok",
        )
        feedback = Feedback(2, 4.0, {(0, 1)}, 1, "native", "native", "vcs-native-abi", "trace.csv", 2, "T2", True, "abi", "ok")
        rows: list[dict[str, object]] = []

        append_row(
            rows,
            args=args,
            seed=Path("seed.bin"),
            seed_id=0,
            parent_seed_id="initial",
            round_name="bootstrap",
            case_name="case",
            input_format="generated",
            input_size_bytes=4,
            mutation_kind="initial",
            result=result,
            case_dir=Path("case"),
            run_log=Path("run.log"),
            assert_log=Path("assert.log"),
            info=info,
            common_coverage=coverage,
            common_backend="sfuzz_firrtl",
            infrastructure_error="",
            feedback=feedback,
            global_ancestor_states={(0, 1)},
            corpus_size=1,
            active_target_index=0,
            active_target=targets[0],
        )

        self.assertEqual(rows[0]["extension"], "target_rotation")
        self.assertEqual(rows[0]["paper_based"], True)
        self.assertEqual(rows[0]["paper_faithful"], False)
        self.assertEqual(rows[0]["active_target_id"], "t0")

    def _manifest(self, entries: list[tuple[str, str]]) -> Path:
        tmp = tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", suffix=".json")
        with tmp:
            tmp.write(
                json.dumps(
                    {
                        "targets": [
                            {
                                "id": target_id,
                                "category": "miss",
                                "module": "MemBlock",
                                "instance": "SimTop.soc.cc_0.tile.core.memBlock",
                                "signal": "target_sig",
                                "annotation": "SURGE_FREQ=1",
                                "selected_ancestors": [ancestor],
                            }
                            for target_id, ancestor in entries
                        ]
                    }
                )
            )
        return Path(tmp.name)


if __name__ == "__main__":
    unittest.main()
