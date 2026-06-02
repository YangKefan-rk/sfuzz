#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from linknan.config import DEFAULT_CONFIG, context_from_config
from linknan.directfuzz_static import write_metadata as write_directfuzz_static_metadata
from linknan.methods.directfuzz import generate_direct_metadata, run_directfuzz
from linknan.methods.profuzz import run_profuzz
from linknan.methods.rfuzz import run_rfuzz
from linknan.methods.sfuzz import run_sfuzz

try:
    from linknan.methods.surgefuzz import run_surgefuzz, write_dev_surge_profile
except ModuleNotFoundError:
    def run_surgefuzz(args: argparse.Namespace, ctx: object) -> int:
        raise SystemExit("SurgeFuzz LinkNan runner module is unavailable in this worktree")

    def write_dev_surge_profile(output_dir: Path) -> None:
        raise SystemExit("SurgeFuzz development profile generator is unavailable in this worktree")


def add_common_vcs_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="SFuzz TOML config path")
    parser.add_argument("--linknan-root", help="LinkNan checkout root")
    parser.add_argument("--sim-dir", type=Path, help="LinkNan sim directory")
    parser.add_argument("--work-dir", type=Path, default=Path("/tmp/sfuzz-linknan"))
    parser.add_argument("--cycles", type=int, help="max VCS simulation cycles")
    parser.add_argument(
        "--no-cycle-limit",
        action="store_true",
        help="do not pass --cycles to xmake simv-run; rely on workload natural finish and --timeout-sec",
    )
    parser.add_argument("--case-prefix", default=None)
    parser.add_argument("--timeout-sec", type=int, default=0, help="per-command timeout; 0 disables")
    parser.add_argument("--build", action="store_true", help="run xmake simv before executing seeds")
    parser.add_argument("--skip-build", action="store_true", help="require an existing simv")
    parser.add_argument("--rebuild-comp", action="store_true", help="force VCS recompilation when building")
    parser.add_argument("--cov", action="store_true", help="pass --cov to build/run")
    parser.add_argument("--run-urg", action="store_true", help="try to parse VCS .vdb with urg")
    parser.add_argument(
        "--firrtl-cov",
        dest="firrtl_cov",
        help=(
            "enable LinkNan FIRRTL/native coverage export, e.g. FIRRTL.common, FIRRTL.mux, or RFuzz.mux-toggle; "
            "requires an instrumented LinkNan build with firrtl-cover.h/.cpp"
        ),
    )
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

    sfuzz = subparsers.add_parser("sfuzz", help="run an online SFuzz loop through real LinkNan VCS")
    add_common_vcs_args(sfuzz)
    add_seed_batch_args(sfuzz)
    sfuzz.add_argument(
        "--batch-replay",
        action="store_true",
        help="legacy mode: run provided SFUZ seeds once without online selection/mutation",
    )
    sfuzz.add_argument("--campaign-runs", type=int, default=8, help="online SFuzz testcase budget")
    sfuzz.add_argument("--rng-seed", type=int, default=1, help="deterministic host RNG seed for mutation order")
    sfuzz.add_argument("--min-energy", type=int, default=1, help="minimum mutations before rotating a corpus seed")
    sfuzz.add_argument("--max-energy", type=int, default=8, help="maximum mutations for high-yield corpus seeds")
    sfuzz.set_defaults(case_prefix="sfuzz", handler=run_sfuzz)

    rfuzz = subparsers.add_parser(
        "rfuzz",
        help="run RFuzz inputs through real LinkNan VCS",
        epilog=(
            "说明：RFuzz 当前入口按处理器验证口径执行真实 LinkNan VCS campaign loop，"
            "输入统一使用 LinkNan 原生 workload .bin/ELF；.sfuz 会被拒绝。"
            "RFuzz.mux-toggle 导出 VCS native mux-select toggle bitmap，作为 RFuzz "
            "在 LinkNan workload 模式下的原生反馈。推荐与 --no-cycle-limit "
            "--timeout-sec 一起使用。"
        ),
    )
    add_common_vcs_args(rfuzz)
    rfuzz.set_defaults(no_cycle_limit=True)
    rfuzz.add_argument(
        "--seed",
        action="append",
        default=[],
        help="normal LinkNan workload .bin/ELF seed; repeatable; .sfuz is rejected",
    )
    rfuzz.add_argument("--input", action="append", default=[], help="alias for --seed; normal workload .bin/ELF only")
    rfuzz.add_argument("--seed-list", type=Path, help="text file with one workload .bin/ELF path per non-comment line")
    rfuzz.add_argument("--seed-dir", type=Path, help="directory containing initial workload .bin/ELF seeds")
    rfuzz.add_argument("--limit", type=int, default=0, help="load at most this many initial workload seeds; 0 means all")
    rfuzz.add_argument("--raw-hex", default="73001000", help="fallback bytes written to a normal .bin workload seed")
    rfuzz.add_argument("--case-name", default="rfuzz-smoke")
    rfuzz.add_argument("--rfuzz-rounds", type=int, default=1, help="number of RFuzz campaign iterations")
    rfuzz.add_argument("--rfuzz-random-seed", type=int, default=1, help="PRNG seed for RFuzz workload mutations")
    rfuzz.add_argument("--rfuzz-max-input-bytes", type=int, default=0, help="truncate mutated workload inputs; 0 disables")
    rfuzz.add_argument(
        "--rfuzz-input-model",
        choices=["linknan-workload-binary-adapter"],
        default="linknan-workload-binary-adapter",
        help=(
            "RFuzz input ABI for LinkNan processor verification; current experiments intentionally use "
            "LinkNan native .bin/ELF workload inputs"
        ),
    )
    rfuzz.add_argument("--rfuzz-toggle-bitmap", type=Path, help="RFuzz mux-toggle bitmap exported for this testcase")
    rfuzz.add_argument(
        "--rfuzz-toggle-bitmap-source",
        choices=["vcs-native-abi", "manual", "dev-generated"],
        default="manual",
        help="provenance of --rfuzz-toggle-bitmap; only vcs-native-abi can be paper-faithful",
    )
    rfuzz.add_argument("--rfuzz-toggle-total", type=int, default=0, help="total RFuzz mux-toggle points")
    rfuzz.add_argument(
        "--rfuzz-valid-source",
        choices=["unknown", "linknan-workload", "unconstrained", "vcs-native-abi", "manual", "vcs-good-trap"],
        default="linknan-workload",
        help="source of the RFuzz validity decision; LinkNan workload mode treats accepted .bin/ELF inputs as valid processor workloads",
    )
    rfuzz.add_argument(
        "--rfuzz-valid",
        choices=["unknown", "true", "false"],
        default="unknown",
        help="current testcase validity when --rfuzz-valid-source can justify it",
    )
    rfuzz.add_argument("--rfuzz-toggle-bitmap-dir", type=Path, help="directory containing VCS native per-case RFuzz bitmap files")
    rfuzz.add_argument("--firrtl-annotated-dir", type=Path, help="parse annotated FIRRTL/VCS files as diagnostic coverage")
    rfuzz.set_defaults(case_prefix="rfuzz", handler=run_rfuzz)

    direct = subparsers.add_parser(
        "directfuzz",
        help="run DirectFuzz seeds through real LinkNan VCS",
        epilog=(
            "说明：DirectFuzz 当前入口按处理器验证口径执行真实 LinkNan VCS campaign loop，"
            "输入统一使用 LinkNan 原生 workload .bin/ELF；.sfuz 会被拒绝。"
            "DirectFuzz.mux-toggle 导出 VCS native per-instance mux-toggle CSV，"
            "配合 static-analysis metadata 计算 target distance 和 energy。"
        ),
    )
    add_common_vcs_args(direct)
    direct.set_defaults(no_cycle_limit=True, firrtl_cov="DirectFuzz.mux-toggle")
    direct.add_argument("--seed", action="append", default=[], help="DirectFuzz workload .bin/.elf path; repeatable")
    direct.add_argument("--seed-list", type=Path, help="text file with one .bin/.elf path per non-comment line")
    direct.add_argument("--seed-dir", type=Path, help="directory containing .bin/.elf workload inputs")
    direct.add_argument("--limit", type=int, default=0, help="import at most this many initial inputs; 0 means all")
    direct.add_argument("--target-instance", required=True)
    direct.add_argument("--metadata", type=Path, required=True, help="DirectFuzz metadata CSV")
    direct.add_argument("--max-execs", type=int, default=0, help="maximum VCS executions; 0 means seeds plus --mutations")
    direct.add_argument("--mutations", type=int, default=8, help="number of feedback-guided DirectFuzz mutation attempts")
    direct.add_argument("--escape-interval", type=int, default=10, help="regular-queue escape interval after target stalls")
    direct.add_argument("--rng-seed", type=int, default=0, help="deterministic mutation RNG seed")
    direct.add_argument(
        "--metadata-source",
        choices=["static-analysis", "dev-generated", "manual"],
        default="manual",
        help=(
            "provenance of the DirectFuzz instance-distance metadata; "
            "dev-generated/manual keep paper_faithful=false"
        ),
    )
    direct.add_argument(
        "--coverage-backend",
        choices=["vcs-log", "dev-mock", "native-file"],
        default="native-file",
        help="native-file consumes DirectFuzz per-instance mux-toggle CSV; dev-mock is only for pipeline debugging",
    )
    direct.add_argument(
        "--native-coverage",
        type=Path,
        help=(
            "static diagnostic CSV exported by the DirectFuzz native ABI: "
            "instance_name,coverage_hex; prefer --native-coverage-pattern for campaigns"
        ),
    )
    direct.add_argument(
        "--native-coverage-pattern",
        help=(
            "per-execution DirectFuzz native coverage CSV pattern; supports "
            "{case_dir}, {input}, {input_stem}, and {exec}"
        ),
    )
    direct.add_argument(
        "--native-coverage-source",
        choices=["vcs-native-abi", "manual", "dev-generated"],
        default="vcs-native-abi",
        help="provenance of --native-coverage; manual/dev-generated keep paper_faithful=false",
    )
    direct.set_defaults(case_prefix="directfuzz", handler=run_directfuzz)

    surge = subparsers.add_parser(
        "surgefuzz",
        help="run SurgeFuzz seeds through real LinkNan VCS",
        epilog=(
            "说明：当前入口执行真实 VCS campaign loop，并使用正常 LinkNan workload "
            ".bin/ELF 输入；.sfuz 会被拒绝。日志健康特征、dev mock trace 或离线 trace "
            "都必须替换为论文定义的 per-cycle score/ancestor coverage ABI 后，才能作为 "
            "paper-faithful SurgeFuzz 数据。推荐与 --no-cycle-limit --timeout-sec 一起使用。"
        ),
    )
    add_common_vcs_args(surge)
    surge.set_defaults(no_cycle_limit=True)
    surge.add_argument("--seed", action="append", default=[], help="SurgeFuzz workload .bin/.elf path; repeatable")
    surge.add_argument("--seed-list", type=Path, help="text file with one .bin/.elf path per non-comment line")
    surge.add_argument("--seed-dir", type=Path, help="directory containing .bin/.elf workload inputs")
    surge.add_argument("--limit", type=int, default=0, help="import at most this many initial inputs; 0 means all")
    surge.add_argument("--max-execs", type=int, default=0, help="maximum VCS executions; 0 means seeds plus --mutations")
    surge.add_argument("--mutations", type=int, default=8, help="number of score-guided SurgeFuzz mutation attempts")
    surge.add_argument("--rng-seed", type=int, default=0, help="deterministic mutation RNG seed")
    surge.add_argument("--max-input-bytes", type=int, default=0, help="truncate mutated workload inputs; 0 disables")
    surge.add_argument("--annotation-type", default="SURGE_FREQ=1")
    surge.add_argument("--target-signal-or-group", default="MSHR")
    surge.add_argument(
        "--score-trace-dir",
        type=Path,
        help=(
            "directory containing <seed-stem>.csv traces; omit for T0 real-VCS "
            "no-trace smoke where SurgeFuzz score fields stay unavailable"
        ),
    )
    surge.add_argument("--score-column", default="coverage_target")
    surge.add_argument(
        "--trace-is-dev-mock",
        action="store_true",
        help="legacy alias for --trace-source dev-mock; never paper-faithful",
    )
    surge.add_argument(
        "--trace-source",
        choices=["vcs-native-abi", "offline-csv", "dev-mock"],
        default="offline-csv",
        help=(
            "provenance of --score-trace-dir; use dev-mock for generated smoke "
            "traces, and only vcs-native-abi can be paper-faithful"
        ),
    )
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

    gen_direct_static = subparsers.add_parser(
        "gen-directfuzz-static-metadata",
        help="generate DirectFuzz static-analysis metadata from LinkNan generated RTL",
    )
    gen_direct_static.add_argument("--rtl-dir", type=Path, required=True)
    gen_direct_static.add_argument("--output", type=Path, required=True)
    gen_direct_static.add_argument("--target-instance", required=True)
    gen_direct_static.add_argument("--top-module", default="SimTop")

    gen_surge = subparsers.add_parser(
        "gen-surgefuzz-dev-profile",
        help="generate a small SurgeFuzz development profile; not paper-faithful data",
    )
    gen_surge.add_argument("--output-dir", type=Path, required=True)

    args = parser.parse_args()
    if args.command == "gen-directfuzz-dev-metadata":
        generate_direct_metadata(args.output.expanduser(), args.target_instance, args.target_module)
        return 0
    if args.command == "gen-directfuzz-static-metadata":
        write_directfuzz_static_metadata(
            args.rtl_dir.expanduser().resolve(),
            args.output.expanduser().resolve(),
            args.target_instance,
            args.top_module,
        )
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
