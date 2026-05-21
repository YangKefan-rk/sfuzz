#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from linknan.config import DEFAULT_CONFIG, context_from_config
from linknan.methods.directfuzz import generate_direct_metadata, run_directfuzz
from linknan.methods.profuzz import run_profuzz
from linknan.methods.rfuzz import run_rfuzz
from linknan.methods.sfuzz import run_sfuzz
from linknan.methods.surgefuzz import run_surgefuzz, write_dev_surge_profile


def add_common_vcs_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="SFuzz TOML config path")
    parser.add_argument("--linknan-root", help="LinkNan checkout root")
    parser.add_argument("--sim-dir", type=Path, help="LinkNan sim directory")
    parser.add_argument("--work-dir", type=Path, default=Path("/tmp/sfuzz-linknan"))
    parser.add_argument("--cycles", type=int, help="max VCS simulation cycles")
    parser.add_argument("--case-prefix", default=None)
    parser.add_argument("--timeout-sec", type=int, default=0, help="per-command timeout; 0 disables")
    parser.add_argument("--build", action="store_true", help="run xmake simv before executing seeds")
    parser.add_argument("--skip-build", action="store_true", help="require an existing simv")
    parser.add_argument("--rebuild-comp", action="store_true", help="force VCS recompilation when building")
    parser.add_argument("--cov", action="store_true", help="pass --cov to build/run")
    parser.add_argument("--run-urg", action="store_true", help="try to parse VCS .vdb with urg")
    parser.add_argument("--simv-args", help="raw arguments passed to simv through xmake --simv_args")
    parser.add_argument("--output-json", type=Path)
    parser.add_argument("--output-csv", type=Path)


def add_seed_batch_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--seed", action="append", default=[], help="SFUZ seed path; repeatable")
    parser.add_argument("--seed-list", type=Path, help="text file with one seed path per non-comment line")
    parser.add_argument("--seed-dir", type=Path, help="directory containing .sfuz seeds")
    parser.add_argument("--limit", type=int, default=0, help="run at most this many seeds; 0 means all")


def validate_common(args: argparse.Namespace) -> None:
    if args.build and args.skip_build:
        raise SystemExit("--build and --skip-build cannot both be set")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run SFuzz, RFuzz, DirectFuzz, and SurgeFuzz on the LinkNan VCS platform",
        epilog=(
            "说明：真实 LinkNan VCS 构建/运行路径已保留。RFuzz/DirectFuzz/SurgeFuzz "
            "凡使用日志、dev mock、VCS built-in coverage 或离线 trace 的覆盖/反馈结果，"
            "必须接入论文定义的真实覆盖/反馈 ABI 后，才能作为 paper-faithful 数据。"
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    sfuzz = subparsers.add_parser("sfuzz", help="run SFuzz SFUZ seeds through real LinkNan VCS")
    add_common_vcs_args(sfuzz)
    add_seed_batch_args(sfuzz)
    sfuzz.set_defaults(case_prefix="sfuzz", handler=run_sfuzz)

    rfuzz = subparsers.add_parser(
        "rfuzz",
        help="run RFuzz inputs through real LinkNan VCS",
        epilog=(
            "说明：当前入口保留真实 VCS 运行。若未提供 RFuzz mux-select bitmap，"
            "覆盖来自日志、VCS built-in coverage 或 FIRRTL 诊断解析时，必须接入论文定义的 "
            "RFuzz mux-select 覆盖/反馈 ABI 后，才能作为 paper-faithful RFuzz 数据。"
        ),
    )
    add_common_vcs_args(rfuzz)
    rfuzz.add_argument("--seed", action="append", default=[], help="existing .sfuz seed; first seed is used")
    rfuzz.add_argument("--raw-hex", default="73001000", help="raw bytes packed into a generated SFUZ core0 payload")
    rfuzz.add_argument("--case-name", default="rfuzz-smoke")
    rfuzz.add_argument("--rfuzz-toggle-bitmap", type=Path, help="external true RFuzz mux-toggle bitmap")
    rfuzz.add_argument("--rfuzz-toggle-total", type=int, default=0, help="total RFuzz mux-toggle points")
    rfuzz.add_argument("--firrtl-annotated-dir", type=Path, help="parse annotated FIRRTL/VCS files as diagnostic coverage")
    rfuzz.set_defaults(case_prefix="rfuzz", handler=run_rfuzz)

    direct = subparsers.add_parser(
        "directfuzz",
        help="run DirectFuzz seeds through real LinkNan VCS",
        epilog=(
            "说明：当前入口保留真实 VCS 运行。vcs-log 和 dev-mock 都不是论文定义的 "
            "DirectFuzz 覆盖/反馈，必须接入 per-instance mux-toggle ABI 后，"
            "才能作为 paper-faithful DirectFuzz 数据。"
        ),
    )
    add_common_vcs_args(direct)
    add_seed_batch_args(direct)
    direct.add_argument("--target-instance", required=True)
    direct.add_argument("--metadata", type=Path, required=True, help="DirectFuzz metadata CSV")
    direct.add_argument(
        "--coverage-backend",
        choices=["vcs-log", "dev-mock", "native-file"],
        default="vcs-log",
        help="native-file consumes DirectFuzz per-instance mux-toggle CSV; dev-mock is only for pipeline debugging",
    )
    direct.add_argument(
        "--native-coverage",
        type=Path,
        help="CSV exported by the DirectFuzz native ABI: instance_name,coverage_hex",
    )
    direct.set_defaults(case_prefix="directfuzz", handler=run_directfuzz)

    surge = subparsers.add_parser(
        "surgefuzz",
        help="run SurgeFuzz seeds through real LinkNan VCS",
        epilog=(
            "说明：当前入口保留真实 VCS 运行。日志健康特征、dev mock trace 或离线 trace "
            "都必须替换为论文定义的 per-cycle score/ancestor coverage ABI 后，"
            "才能作为 paper-faithful SurgeFuzz 数据。"
        ),
    )
    add_common_vcs_args(surge)
    add_seed_batch_args(surge)
    surge.add_argument("--annotation-type", default="SURGE_FREQ=1")
    surge.add_argument("--target-signal-or-group", default="MSHR")
    surge.add_argument("--score-trace-dir", type=Path, help="directory containing <seed-stem>.csv traces")
    surge.add_argument("--score-column", default="coverage_target")
    surge.add_argument("--trace-is-dev-mock", action="store_true")
    surge.add_argument("--freq-window", type=int, default=256)
    surge.set_defaults(case_prefix="surgefuzz", handler=run_surgefuzz)

    profuzz = subparsers.add_parser(
        "profuzz",
        help="reserved PROFUZZ LinkNan/VCS entry",
        epilog="说明：PROFUZZ 必须先接入论文定义的目标点覆盖/反馈 ABI。",
    )
    add_common_vcs_args(profuzz)
    profuzz.set_defaults(case_prefix="profuzz", handler=run_profuzz)

    gen_direct = subparsers.add_parser(
        "gen-directfuzz-dev-metadata",
        help="generate a small DirectFuzz development metadata CSV; not static-analysis output",
    )
    gen_direct.add_argument("--output", type=Path, required=True)
    gen_direct.add_argument("--target-instance", required=True)
    gen_direct.add_argument("--target-module", default="")

    gen_surge = subparsers.add_parser(
        "gen-surgefuzz-dev-profile",
        help="generate a small SurgeFuzz development profile; not paper-faithful data",
    )
    gen_surge.add_argument("--output-dir", type=Path, required=True)

    args = parser.parse_args()
    if args.command == "gen-directfuzz-dev-metadata":
        generate_direct_metadata(args.output.expanduser(), args.target_instance, args.target_module)
        return 0
    if args.command == "gen-surgefuzz-dev-profile":
        write_dev_surge_profile(args.output_dir.expanduser())
        return 0

    validate_common(args)
    if args.case_prefix is None:
        args.case_prefix = args.command
    ctx = context_from_config(args)
    return args.handler(args, ctx)


if __name__ == "__main__":
    raise SystemExit(main())
