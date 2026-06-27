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
    from linknan.surgefuzz_profile import run_surgefuzz_profile
    from linknan.surgefuzz_targets import DEFAULT_TARGET_MANIFEST
except ModuleNotFoundError:
    DEFAULT_TARGET_MANIFEST = Path("config/surgefuzz_targets.toml")

    def run_surgefuzz(args: argparse.Namespace, ctx: object) -> int:
        raise SystemExit("SurgeFuzz LinkNan runner module is unavailable in this worktree")

    def write_dev_surge_profile(output_dir: Path) -> None:
        raise SystemExit("SurgeFuzz development profile generator is unavailable in this worktree")

    def run_surgefuzz_profile(args: argparse.Namespace, ctx: object) -> int:
        raise SystemExit("SurgeFuzz LinkNan profile collector is unavailable in this worktree")


def add_common_vcs_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="SFuzz TOML config path")
    parser.add_argument("--linknan-root", help="LinkNan checkout root")
    parser.add_argument("--build-dir", type=Path, help="LinkNan build directory")
    parser.add_argument("--sim-dir", type=Path, help="LinkNan sim directory")
    parser.add_argument("--work-dir", type=Path, default=Path("/tmp/sfuzz-linknan"))
    parser.add_argument("--cycles", type=int, help="max VCS simulation cycles")
    parser.add_argument(
        "--no-cycle-limit",
        action="store_true",
        help="do not pass --cycles to xmake simv-run; rely on workload natural finish and --timeout-sec",
    )
    parser.add_argument(
        "--tohost-addr",
        default="auto",
        help=(
            "HTIF tohost completion monitor address for bare riscv-test workloads. "
            "'auto' (default) reads the tohost symbol from ELF seeds; a hex/decimal "
            "literal sets it explicitly; 'off' disables the monitor."
        ),
    )
    parser.add_argument("--case-prefix", default=None)
    parser.add_argument("--timeout-sec", type=int, default=0, help="per-command timeout; 0 disables")
    parser.add_argument(
        "--build-timeout-sec",
        type=int,
        default=0,
        help="VCS build timeout; 0 reuses --timeout-sec, so run-time wall timeout semantics stay compatible",
    )
    parser.add_argument("--build", action="store_true", help="run xmake simv before executing seeds")
    parser.add_argument("--skip-build", action="store_true", help="require an existing simv")
    parser.add_argument(
        "--build-chisel",
        action="store_true",
        help="regenerate LinkNan Chisel/RTL before VCS compilation; needed after Scala design changes",
    )
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
    sfuzz.add_argument(
        "--scheduler-policy",
        choices=["weighted-innovation", "semantic-bandit", "baseline-fifo", "coverage-weighted-energy"],
        default="weighted-innovation",
        help="SFuzz corpus scheduler; semantic-bandit adds exploration-aware semantic feedback",
    )
    sfuzz.add_argument(
        "--mutation-sections",
        default="core0,core1,shared,interrupt",
        help="comma-separated SFUZ sections to mutate: core0,core1,shared,interrupt,all",
    )
    sfuzz.add_argument(
        "--disable-semantic-mutation",
        action="store_true",
        help="ablation: use legacy byte/section mutation instead of SFuzz semantic scenario mutation",
    )
    sfuzz.add_argument(
        "--disable-scenario-aware-scheduling",
        action="store_true",
        help="ablation: ignore SFUZZ.native group deficits when selecting semantic operators",
    )
    sfuzz.add_argument(
        "--enable-core1-handoff",
        action="store_true",
        help="mark generated two-core scenarios as formal results only after LinkNan core1 execution handoff is enabled",
    )
    sfuzz.add_argument(
        "--target-min-wall-time-sec",
        type=int,
        default=0,
        help="mark shorter SFuzz executions as short_run for formal campaign filtering",
    )
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
    rfuzz.add_argument(
        "--formal-campaign-total-execs",
        type=int,
        default=0,
        help="total executions across all parallel workers for formal campaign guards",
    )
    rfuzz.add_argument(
        "--require-formal-feedback",
        action="store_true",
        help="reject RFuzz runs that do not meet the LinkNan workload formal campaign checks",
    )
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
    direct.add_argument(
        "--formal-campaign-total-execs",
        type=int,
        default=0,
        help="total executions across all parallel workers for formal campaign guards",
    )
    direct.add_argument(
        "--require-paper-native",
        action="store_true",
        help="reject DirectFuzz runs unless native per-instance feedback and static distance metadata are used",
    )
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
    surge.set_defaults(no_cycle_limit=True, firrtl_cov="SurgeFuzz.trace")
    surge.add_argument(
        "--input-mode",
        choices=["artifact-program", "workload"],
        default="artifact-program",
        help="artifact-program reproduces SurgeFuzz Program/Block/Instruction mutation; workload keeps the legacy .bin/.elf adapter",
    )
    surge.add_argument("--seed", action="append", default=[], help="legacy workload .bin/.elf path; repeatable")
    surge.add_argument("--seed-list", type=Path, help="text file with one .bin/.elf path per non-comment line")
    surge.add_argument("--seed-dir", type=Path, help="directory containing .bin/.elf workload inputs")
    surge.add_argument("--limit", type=int, default=0, help="import at most this many initial inputs; 0 means all")
    surge.add_argument("--max-execs", type=int, default=0, help="maximum VCS executions; 0 means seeds plus --mutations")
    surge.add_argument("--mutations", type=int, default=8, help="number of score-guided SurgeFuzz mutation attempts")
    surge.add_argument(
        "--formal-campaign-total-execs",
        type=int,
        default=0,
        help="total executions across all parallel workers for formal campaign guards",
    )
    surge.add_argument(
        "--require-paper-native",
        action="store_true",
        help="reject SurgeFuzz runs unless single-target native trace feedback and artifact mutation are used",
    )
    surge.add_argument("--rng-seed", type=int, default=0, help="deterministic mutation RNG seed")
    surge.add_argument("--max-input-bytes", type=int, default=0, help="truncate mutated workload inputs; 0 disables")
    surge.add_argument("--annotation-type", default=None, help="override selected manifest target annotation")
    surge.add_argument("--target-signal-or-group", default=None, help="override selected manifest target signal/group label")
    surge.add_argument("--target-manifest", type=Path, default=DEFAULT_TARGET_MANIFEST)
    surge.add_argument("--surge-target", default="memblock_load_miss", help="target id from --target-manifest")
    surge.add_argument("--ancestor-selector", choices=["manual", "distance", "distance-nmi"], default="")
    surge.add_argument("--ancestor-profile", default="", help="optional profile CSV for distance-nmi pruning")
    surge.add_argument("--max-surgefuzz-ancestor-width", type=int, default=0)
    surge.add_argument(
        "--rotation-manifest",
        type=Path,
        help=(
            "SurgeFuzz target-rotation manifest generated by surgefuzz-profile; "
            "this is a paper-based extension, not paper-native SurgeFuzz"
        ),
    )
    surge.add_argument(
        "--rotation-mode",
        choices=["none", "round-robin", "fixed-budget", "stall-based"],
        default="none",
        help="schedule across multiple SurgeFuzz targets; any non-none value marks paper_faithful=false",
    )
    surge.add_argument(
        "--rotation-budget-per-target",
        type=int,
        default=8,
        help="executions before switching targets in fixed-budget rotation mode",
    )
    surge.add_argument(
        "--rotation-stall-threshold",
        type=int,
        default=8,
        help="switch target after this many no-new-coverage executions in stall-based rotation mode",
    )
    surge.add_argument(
        "--disable-mi",
        action="store_true",
        help="ablation: use distance-only ancestor selections from the rotation manifest",
    )
    surge.add_argument(
        "--disable-power-scheduling",
        action="store_true",
        help="ablation: select corpus seeds with fixed energy instead of score^2",
    )
    surge.add_argument("--initial-seed-count", type=int, default=1)
    surge.add_argument("--initial-seed-block-count", type=int, default=4)
    surge.add_argument("--initial-seed-instructions-per-block", type=int, default=5)
    surge.add_argument("--max-operation-count", type=int, default=3)
    surge.add_argument("--enable-rv64a", action="store_true", default=False)
    surge.add_argument("--disable-rv64a", dest="enable_rv64a", action="store_false")
    surge.add_argument("--enable-rv64im", action="store_true", default=False)
    surge.add_argument("--disable-rv64im", dest="enable_rv64im", action="store_false")
    surge.add_argument("--enable-insert-memory-access-sequence", dest="enable_insert_memory_access_sequence", action="store_true", default=True)
    surge.add_argument("--disable-insert-memory-access-sequence", dest="enable_insert_memory_access_sequence", action="store_false")
    surge.add_argument("--surgefuzz-riscv-gcc", default="")
    surge.add_argument("--surgefuzz-objcopy", default="")
    surge.add_argument("--link-address", default="0x80000000")
    surge.add_argument("--test-memory-bytes", type=int, default=4096)
    surge.add_argument("--stack-bytes", type=int, default=4096)
    surge.add_argument("--asm-header", type=Path)
    surge.add_argument("--asm-footer", type=Path)
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
    surge.set_defaults(trace_source="vcs-native-abi")
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
    gen_direct_static.add_argument(
        "--max-directfuzz-mux",
        type=int,
        default=0,
        help="DirectFuzz mux metadata budget; 0 means all muxes and matches LinkNan default",
    )
    gen_direct_static.add_argument(
        "--graph-output-dir",
        type=Path,
        help="optional directory for DirectFuzz signal-direction graph audit CSVs",
    )

    gen_surge = subparsers.add_parser(
        "gen-surgefuzz-dev-profile",
        help="generate a small SurgeFuzz development profile; not paper-faithful data",
    )
    gen_surge.add_argument("--output-dir", type=Path, required=True)

    surge_profile = subparsers.add_parser(
        "surgefuzz-profile",
        help="collect real LinkNan per-target SurgeFuzz profiles and generate an ancestor/rotation manifest",
        epilog=(
            "说明：该命令先对每个 target 用真实 LinkNan workload 采样 coverage_target 和候选 ancestor，"
            "然后在 sfuzz 侧执行 distance + MI/NMI pruning。LinkNan 只负责按显式 target/ancestor 配置插装导出。"
        ),
    )
    add_common_vcs_args(surge_profile)
    surge_profile.set_defaults(no_cycle_limit=True, firrtl_cov="SurgeFuzz.trace")
    surge_profile.add_argument("--target-manifest", type=Path, default=DEFAULT_TARGET_MANIFEST)
    surge_profile.add_argument(
        "--profile-target",
        action="append",
        default=[],
        help="target id to profile; repeatable; defaults to all targets in --target-manifest",
    )
    surge_profile.add_argument("--profile-seed", action="append", default=[], help="workload .bin/.elf used for profile sampling")
    surge_profile.add_argument("--profile-seed-list", type=Path, help="text file with one profile workload per line")
    surge_profile.add_argument("--profile-seed-dir", type=Path, help="directory containing .bin/.elf profile workloads")
    surge_profile.add_argument("--profile-seed-limit", type=int, default=0, help="profile at most this many workloads")
    surge_profile.add_argument(
        "--profile-fallback-seed",
        default="",
        help="single fallback workload path when no profile seed/list/dir is provided",
    )
    surge_profile.add_argument(
        "--profile-max-candidates",
        type=int,
        default=256,
        help="maximum candidate ancestor signals sampled per target; 0 means all candidates",
    )
    surge_profile.add_argument(
        "--profile-min-scope-candidates",
        type=int,
        default=64,
        help="extend weak distance-only target scopes with related control/register candidates up to this count; 0 disables",
    )
    surge_profile.add_argument(
        "--profile-chunk-bits",
        type=int,
        default=64,
        help="maximum packed ancestor width per profile VCS build/run chunk",
    )
    surge_profile.add_argument(
        "--profile-max-candidate-width",
        type=int,
        default=8,
        help="maximum width of a single signal sampled during profile collection; 0 disables this filter",
    )
    surge_profile.add_argument(
        "--profile-include-wide-candidates",
        action="store_true",
        help="allow addr/pc/data-style wide bus signals in profile collection",
    )
    surge_profile.add_argument(
        "--profile-nmi-threshold",
        type=float,
        default=0.85,
        help="NMI threshold for pruning redundant ancestor candidates",
    )
    surge_profile.add_argument("--profile-no-mi", action="store_true", help="select distance-only ancestors")
    surge_profile.add_argument("--max-surgefuzz-ancestor-width", type=int, default=64)
    surge_profile.add_argument("--rotation-manifest", type=Path, help="output JSON manifest for target rotation")
    surge_profile.set_defaults(case_prefix="surgefuzz-profile", handler=run_surgefuzz_profile)

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
            args.max_directfuzz_mux,
            args.graph_output_dir.expanduser().resolve() if args.graph_output_dir else None,
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
