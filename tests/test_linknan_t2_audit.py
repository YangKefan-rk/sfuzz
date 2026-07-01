from __future__ import annotations

import csv
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from linknan.audit_t2_campaign import audit_method, is_mutation_row  # noqa: E402


class T2CampaignAuditTests(unittest.TestCase):
    def test_mutation_rows_are_not_inferred_from_empty_fields(self) -> None:
        self.assertFalse(
            is_mutation_row(
                {
                    "fuzzer": "sfuzz",
                    "mutation_index": "",
                    "mutation": "",
                    "mutation_kind": "",
                    "semantic_operator": "",
                    "round": "",
                }
            )
        )
        self.assertFalse(is_mutation_row({"fuzzer": "sfuzz", "mutation_index": "", "semantic_operator": "insert_amo_sequence"}))
        self.assertTrue(is_mutation_row({"fuzzer": "sfuzz", "mutation_index": "1", "semantic_operator": "insert_amo_sequence"}))
        self.assertFalse(is_mutation_row({"fuzzer": "rfuzz", "mutation": "initial-workload", "round": "1"}))
        self.assertTrue(is_mutation_row({"fuzzer": "rfuzz", "mutation": "arith8+1[4]", "round": "2"}))
        self.assertFalse(is_mutation_row({"fuzzer": "directfuzz", "mutation": "initial-workload", "mutation_index": "seed"}))
        self.assertTrue(is_mutation_row({"fuzzer": "directfuzz", "mutation": "havoc", "mutation_index": "2"}))
        self.assertFalse(
            is_mutation_row(
                {
                    "fuzzer": "surgefuzz",
                    "round": "bootstrap",
                    "mutation_kind": "initial-artifact-program",
                }
            )
        )
        self.assertTrue(
            is_mutation_row(
                {
                    "fuzzer": "surgefuzz",
                    "round": "0",
                    "mutation_kind": "artifact-program-mutation",
                }
            )
        )

    def test_surgefuzz_trace_sample_limit_is_not_required_for_existing_meta(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            worker = root / "results" / "surgefuzz" / "workers" / "worker-000"
            case_dir = worker / "work" / "vcs-runs" / "case-0"
            case_dir.mkdir(parents=True)
            command_log = worker / "cmd.log"
            command_log.write_text("COMMAND: xmake simv-run --no_diff\n", encoding="utf-8")
            csv_path = worker / "results.csv"
            fields = [
                "fuzzer",
                "round",
                "mutation_kind",
                "case_dir",
                "command_log_path",
                "timed_out",
                "design_bug",
                "invalid_input",
                "paper_faithful",
                "required_native_abi",
                "coverage_backend",
                "trace_source",
                "trace_rows",
                "trace_truncated",
                "trace_sample_limit",
                "trace_call_count",
                "trace_target_hit_count",
            ]
            with csv_path.open("w", newline="", encoding="utf-8") as output:
                writer = csv.DictWriter(output, fieldnames=fields)
                writer.writeheader()
                writer.writerow(
                    {
                        "fuzzer": "surgefuzz",
                        "round": "0",
                        "mutation_kind": "artifact-program-mutation",
                        "case_dir": str(case_dir),
                        "command_log_path": str(command_log),
                        "timed_out": "True",
                        "design_bug": "False",
                        "invalid_input": "False",
                        "paper_faithful": "True",
                        "required_native_abi": "",
                        "coverage_backend": "surgefuzz_vcs_native_abi_trace",
                        "trace_source": "vcs-native-abi",
                        "trace_rows": "1048576",
                        "trace_truncated": "True",
                        "trace_sample_limit": "",
                        "trace_call_count": "3000000",
                        "trace_target_hit_count": "7",
                    }
                )

            audit = audit_method(root, "surgefuzz", expected_rows=1, complete=True)
            self.assertEqual(audit.rows, 1)
            self.assertEqual(audit.mutation_rows, 1)
            self.assertEqual(audit.issues, [])

    def test_surgefuzz_timeout_trace_summary_can_be_recovered_from_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            worker = root / "results" / "surgefuzz" / "workers" / "worker-000"
            case_dir = worker / "work" / "vcs-runs" / "case-0"
            case_dir.mkdir(parents=True)
            command_log = worker / "cmd.log"
            command_log.write_text("COMMAND: xmake simv-run --no_diff\n", encoding="utf-8")
            trace = case_dir / "surgefuzz_trace.csv"
            trace.write_text(
                "cycle,coverage_target,dependent_0\n"
                "0,0,1\n"
                "1,1,2\n"
                "2,0,2\n",
                encoding="utf-8",
            )
            csv_path = worker / "results.csv"
            fields = [
                "fuzzer",
                "round",
                "mutation_kind",
                "case_dir",
                "command_log_path",
                "timed_out",
                "design_bug",
                "invalid_input",
                "paper_faithful",
                "required_native_abi",
                "coverage_backend",
                "trace_source",
                "trace_path",
                "trace_rows",
                "trace_call_count",
                "trace_target_hit_count",
            ]
            with csv_path.open("w", newline="", encoding="utf-8") as output:
                writer = csv.DictWriter(output, fieldnames=fields)
                writer.writeheader()
                writer.writerow(
                    {
                        "fuzzer": "surgefuzz",
                        "round": "0",
                        "mutation_kind": "artifact-program-mutation",
                        "case_dir": str(case_dir),
                        "command_log_path": str(command_log),
                        "timed_out": "True",
                        "design_bug": "False",
                        "invalid_input": "False",
                        "paper_faithful": "True",
                        "required_native_abi": "",
                        "coverage_backend": "surgefuzz_vcs_native_abi_trace",
                        "trace_source": "vcs-native-abi",
                        "trace_path": str(trace),
                        "trace_rows": "3",
                        "trace_call_count": "",
                        "trace_target_hit_count": "",
                    }
                )

            audit = audit_method(root, "surgefuzz", expected_rows=1, complete=True)

            self.assertEqual(audit.issues, [])
            self.assertEqual(audit.counters["trace_summary_fallback"], {"csv_samples": 1})


if __name__ == "__main__":
    unittest.main()
