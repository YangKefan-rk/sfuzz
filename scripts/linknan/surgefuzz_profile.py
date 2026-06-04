from __future__ import annotations

import csv
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .common import now_iso, require_file, slugify
from .config import VcsContext
from .surgefuzz_ancestors import (
    AncestorCandidate,
    normalized_mutual_information,
    select_ancestor_names,
    signal_name_for_profile,
    target_distance_candidates,
)
from .surgefuzz_targets import SurgeTarget, load_target_manifest
from .vcs import (
    SFUZZ_FIRRTL_COV_ENV,
    SFUZZ_FIRRTL_COV_OUT_ENV,
    build_simv_if_needed,
    run_vcs_seed,
)


DECL_RE = re.compile(
    r"^\s*(input|output|wire|logic|reg)\s+"
    r"(?:(?:signed|unsigned)\s+)?"
    r"((?:\[[^\]]+\]\s*)*)"
    r"([A-Za-z_][A-Za-z0-9_$]*)\b"
)
MODULE_RE = re.compile(r"\bmodule\s+([A-Za-z_][A-Za-z0-9_$]*)\b")
PROFILE_WIDE_BUS_TOKENS = (
    "addr",
    "address",
    "vaddr",
    "paddr",
    "pc",
    "data",
    "bits",
    "mask",
    "wdata",
    "rdata",
)


@dataclass(frozen=True)
class RtlSignal:
    name: str
    width: int
    direction: str


@dataclass(frozen=True)
class RtlModule:
    name: str
    body: str
    signals: dict[str, RtlSignal]


@dataclass(frozen=True)
class ProfileWorkload:
    path: Path
    label: str


@dataclass(frozen=True)
class TargetSelection:
    target: SurgeTarget
    candidates: list[AncestorCandidate]
    selected: list[str]
    distance_selected: list[str]
    mi_selected: list[str]
    selection_meta: dict[str, object]
    distance_selection_meta: dict[str, object]
    mi_selection_meta: dict[str, object]
    profile_csv: Path
    candidates_csv: Path
    selected_csv: Path
    nmi_report_csv: Path
    meta_json: Path


def width_from_dims(dims: str) -> int:
    width = 1
    for match in re.finditer(r"\[\s*(\d+)\s*:\s*(\d+)\s*\]", dims or ""):
        left = int(match.group(1))
        right = int(match.group(2))
        width *= abs(left - right) + 1
    return max(1, width)


def strip_sv_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//.*", "", text)


def parse_rtl_modules(rtl_dir: Path) -> dict[str, RtlModule]:
    modules: dict[str, RtlModule] = {}
    for path in sorted(rtl_dir.glob("*.sv")):
        text = strip_sv_comments(path.read_text(encoding="utf-8", errors="replace"))
        for match in MODULE_RE.finditer(text):
            name = match.group(1)
            next_match = MODULE_RE.search(text, match.end())
            body = text[match.start() : next_match.start() if next_match else len(text)]
            signals: dict[str, RtlSignal] = {}
            for line in body.splitlines():
                decl = DECL_RE.match(line)
                if decl is None:
                    continue
                kind, dims, signal_name = decl.groups()
                signals.setdefault(signal_name, RtlSignal(signal_name, width_from_dims(dims), kind))
            modules[name] = RtlModule(name, body, signals)
    return modules


def write_candidate_csv(path: Path, candidates: list[AncestorCandidate]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(
            output_file,
            fieldnames=["name", "width", "direction", "depth", "register_depth", "is_control", "source"],
        )
        writer.writeheader()
        for candidate in candidates:
            writer.writerow(
                {
                    "name": candidate.name,
                    "width": candidate.width,
                    "direction": candidate.direction,
                    "depth": candidate.depth,
                    "register_depth": candidate.register_depth,
                    "is_control": int(candidate.is_control),
                    "source": candidate.source,
                }
            )


def write_selected_csv(path: Path, selected: list[str], candidates: list[AncestorCandidate]) -> None:
    candidate_by_name = {candidate.name: candidate for candidate in candidates}
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=["index", "name", "width", "depth", "register_depth", "is_control"])
        writer.writeheader()
        for index, name in enumerate(selected):
            base = name.split("[", 1)[0]
            candidate = candidate_by_name.get(base)
            width = candidate.width if candidate is not None else 1
            slice_match = re.search(r"\[\s*(\d+)(?:\s*:\s*(\d+))?\s*\]", name)
            if slice_match:
                high = int(slice_match.group(1))
                low = int(slice_match.group(2) if slice_match.group(2) is not None else slice_match.group(1))
                width = abs(high - low) + 1
            writer.writerow(
                {
                    "index": index,
                    "name": name,
                    "width": width,
                    "depth": candidate.depth if candidate is not None else "",
                    "register_depth": candidate.register_depth if candidate is not None else "",
                    "is_control": int(candidate.is_control) if candidate is not None else "",
                }
            )


def write_profile_candidate_map(path: Path, candidates: list[AncestorCandidate]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=["index", "profile_column", "signal_name", "width"])
        writer.writeheader()
        for index, candidate in enumerate(candidates):
            writer.writerow(
                {
                    "index": index,
                    "profile_column": f"dependent_{index}",
                    "signal_name": candidate.name,
                    "width": candidate.width,
                }
            )


def read_profile_samples(path: Path) -> dict[str, list[int]]:
    samples: dict[str, list[int]] = {}
    with path.open(newline="", encoding="utf-8") as input_file:
        reader = csv.DictReader(input_file)
        for row in reader:
            for key, value in row.items():
                if key in {"cycle", "workload", "chunk"} or value in {None, ""}:
                    continue
                try:
                    samples.setdefault(key, []).append(int(value, 0))
                except ValueError:
                    continue
    return samples


def read_profile_pairs(path: Path, rhs: str) -> dict[str, tuple[list[int], list[int]]]:
    pairs: dict[str, tuple[list[int], list[int]]] = {}
    with path.open(newline="", encoding="utf-8") as input_file:
        reader = csv.DictReader(input_file)
        for row in reader:
            rhs_raw = row.get(rhs)
            if rhs_raw in {None, ""}:
                continue
            try:
                rhs_value = int(rhs_raw, 0)
            except ValueError:
                continue
            for key, value in row.items():
                if key in {"cycle", "workload", "chunk", rhs} or value in {None, ""}:
                    continue
                try:
                    lhs_value = int(value, 0)
                except ValueError:
                    continue
                lhs_values, rhs_values = pairs.setdefault(key, ([], []))
                lhs_values.append(lhs_value)
                rhs_values.append(rhs_value)
    return pairs


def profile_candidate_quality(candidates: list[AncestorCandidate], profile_csv: Path) -> dict[str, object]:
    if not profile_csv.is_file():
        return {
            "profile_csv": str(profile_csv),
            "profile_exists": False,
            "profile_row_count": 0,
            "candidate_count": len(candidates),
            "profiled_candidate_count": 0,
            "varying_candidate_count": 0,
            "target_sample_count": 0,
            "target_distinct_values": 0,
            "nmi": {},
        }

    pairs = read_profile_pairs(profile_csv, "coverage_target")
    profile_row_count = 0
    target_values: list[int] = []
    with profile_csv.open(newline="", encoding="utf-8") as input_file:
        reader = csv.DictReader(input_file)
        for row in reader:
            profile_row_count += 1
            raw = row.get("coverage_target")
            if raw in {None, ""}:
                continue
            try:
                target_values.append(int(raw, 0))
            except ValueError:
                continue

    profiled = 0
    varying = 0
    missing = 0
    constant = 0
    nmi_values: list[float] = []
    zero_nmi = 0
    high_nmi = 0
    samples_by_candidate: dict[str, int] = {}
    for candidate in candidates:
        name = signal_name_for_profile(candidate.name)
        candidate_samples, target_samples = pairs.get(name, ([], []))
        samples_by_candidate[candidate.name] = len(candidate_samples)
        if not candidate_samples or not target_samples:
            missing += 1
            continue
        profiled += 1
        if len(set(candidate_samples)) <= 1:
            constant += 1
            continue
        varying += 1
        nmi = normalized_mutual_information(candidate_samples, target_samples)
        nmi_values.append(nmi)
        if nmi == 0.0:
            zero_nmi += 1
        if nmi > 0.85:
            high_nmi += 1

    nmi_values.sort()

    def percentile(values: list[float], fraction: float) -> float:
        if not values:
            return 0.0
        index = min(len(values) - 1, max(0, int(round((len(values) - 1) * fraction))))
        return values[index]

    return {
        "profile_csv": str(profile_csv),
        "profile_exists": True,
        "profile_row_count": profile_row_count,
        "candidate_count": len(candidates),
        "profiled_candidate_count": profiled,
        "missing_profile_candidate_count": missing,
        "varying_candidate_count": varying,
        "constant_candidate_count": constant,
        "target_sample_count": len(target_values),
        "target_distinct_values": len(set(target_values)),
        "nmi": {
            "count": len(nmi_values),
            "min": round(nmi_values[0], 9) if nmi_values else 0.0,
            "p25": round(percentile(nmi_values, 0.25), 9),
            "median": round(percentile(nmi_values, 0.50), 9),
            "p75": round(percentile(nmi_values, 0.75), 9),
            "max": round(nmi_values[-1], 9) if nmi_values else 0.0,
            "zero_count": zero_nmi,
            "high_gt_0_85_count": high_nmi,
        },
        "sample_count_min": min(samples_by_candidate.values(), default=0),
        "sample_count_max": max(samples_by_candidate.values(), default=0),
    }


def write_nmi_report(path: Path, candidates: list[AncestorCandidate], profile_csv: Path, selected: list[str]) -> None:
    selected_bases = {item.split("[", 1)[0] for item in selected}
    pairs = read_profile_pairs(profile_csv, "coverage_target")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(
            output_file,
            fieldnames=[
                "name",
                "width",
                "depth",
                "register_depth",
                "is_control",
                "selected",
                "samples",
                "nmi_with_target",
            ],
        )
        writer.writeheader()
        for candidate in candidates:
            candidate_samples, target_samples = pairs.get(candidate.name, ([], []))
            nmi = normalized_mutual_information(candidate_samples, target_samples) if candidate_samples and target_samples else 0.0
            writer.writerow(
                {
                    "name": candidate.name,
                    "width": candidate.width,
                    "depth": candidate.depth,
                    "register_depth": candidate.register_depth,
                    "is_control": int(candidate.is_control),
                    "selected": int(candidate.name in selected_bases),
                    "samples": len(candidate_samples),
                    "nmi_with_target": f"{nmi:.9f}",
                }
            )


def chunk_candidates(candidates: list[AncestorCandidate], *, max_bits: int, max_candidates: int) -> list[list[AncestorCandidate]]:
    chunks: list[list[AncestorCandidate]] = []
    current: list[AncestorCandidate] = []
    width = 0
    for candidate in candidates[:max_candidates if max_candidates > 0 else None]:
        candidate_width = max(1, candidate.width)
        if current and width + candidate_width > max_bits:
            chunks.append(current)
            current = []
            width = 0
        if candidate_width > max_bits:
            chunks.append([candidate])
            continue
        current.append(candidate)
        width += candidate_width
    if current:
        chunks.append(current)
    return chunks


def profile_candidate_subset(
    candidates: list[AncestorCandidate],
    *,
    max_bits: int,
    max_candidates: int,
    max_candidate_width: int,
    include_wide_candidates: bool = False,
) -> tuple[list[AncestorCandidate], dict[str, object]]:
    bit_budget = max(1, max_bits)
    candidate_budget = max_candidates if max_candidates > 0 else len(candidates)
    width_limit = max_candidate_width if max_candidate_width > 0 else bit_budget
    skipped: list[dict[str, object]] = []
    accepted: list[AncestorCandidate] = []
    used_bits = 0
    seen: set[str] = set()

    def skip(candidate: AncestorCandidate, reason: str) -> None:
        if len(skipped) < 128:
            skipped.append({"name": candidate.name, "width": candidate.width, "reason": reason})

    def score(candidate: AncestorCandidate) -> tuple[int, int, int, int, int, str]:
        lower = candidate.name.lower()
        wide_bus_penalty = int(any(token in lower for token in PROFILE_WIDE_BUS_TOKENS))
        source_penalty = 0 if candidate.source.startswith("distance:") else 1
        return (
            wide_bus_penalty,
            0 if candidate.is_control else 1,
            candidate.register_depth,
            candidate.depth,
            source_penalty,
            candidate.name,
        )

    for candidate in sorted(candidates, key=score):
        if len(accepted) >= candidate_budget or used_bits >= bit_budget:
            break
        if candidate.name in seen:
            continue
        seen.add(candidate.name)
        candidate_width = max(1, candidate.width)
        lower = candidate.name.lower()
        looks_like_wide_bus = any(token in lower for token in PROFILE_WIDE_BUS_TOKENS)
        if candidate_width > bit_budget:
            skip(candidate, "exceeds_profile_bit_budget")
            continue
        if not include_wide_candidates and max_candidate_width > 0 and candidate_width > width_limit:
            skip(candidate, "exceeds_profile_candidate_width")
            continue
        if not include_wide_candidates and looks_like_wide_bus and candidate_width > 1:
            skip(candidate, "wide_bus_name")
            continue
        if used_bits + candidate_width > bit_budget:
            skip(candidate, "exceeds_remaining_profile_bits")
            continue
        accepted.append(candidate)
        used_bits += candidate_width

    skipped_by_reason: dict[str, int] = {}
    for item in skipped:
        reason = str(item["reason"])
        skipped_by_reason[reason] = skipped_by_reason.get(reason, 0) + 1
    meta = {
        "input_candidate_count": len(candidates),
        "sampled_candidate_count": len(accepted),
        "sampled_width": used_bits,
        "max_bits": bit_budget,
        "max_candidates": candidate_budget,
        "max_candidate_width": max_candidate_width,
        "include_wide_candidates": include_wide_candidates,
        "skipped_count": len(candidates) - len(accepted),
        "skipped_by_reason": skipped_by_reason,
        "skipped": skipped,
    }
    return accepted, meta


def trace_to_named_profile_rows(
    trace_csv: Path,
    workload: ProfileWorkload,
    chunk_index: int,
    candidates: list[AncestorCandidate],
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    dependent_names = [candidate.name for candidate in candidates]
    with trace_csv.open(newline="", encoding="utf-8") as input_file:
        reader = csv.DictReader(input_file)
        for row in reader:
            out = {
                "cycle": row.get("cycle", ""),
                "workload": workload.label,
                "chunk": str(chunk_index),
                "coverage_target": row.get("coverage_target", "0"),
            }
            for index, name in enumerate(dependent_names):
                out[name] = row.get(f"dependent_{index}", "0")
            rows.append(out)
    return rows


def merge_profile_rows(path: Path, rows: list[dict[str, str]]) -> None:
    fieldnames: list[str] = ["cycle", "workload", "chunk", "coverage_target"]
    seen = set(fieldnames)
    for row in rows:
        for key in row:
            if key not in seen:
                seen.add(key)
                fieldnames.append(key)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def collect_profile_workloads(args: Any) -> list[ProfileWorkload]:
    paths: list[Path] = []
    for item in getattr(args, "profile_seed", []) or []:
        paths.append(Path(item).expanduser())
    list_path = getattr(args, "profile_seed_list", None)
    if list_path:
        list_path = list_path.expanduser()
        base = list_path.resolve().parent
        for raw in list_path.read_text(encoding="utf-8").splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            path = Path(line).expanduser()
            paths.append(path if path.is_absolute() else base / path)
    directory = getattr(args, "profile_seed_dir", None)
    if directory:
        for pattern in ("*.bin", "*.elf"):
            paths.extend(sorted(directory.expanduser().glob(pattern)))
    if not paths:
        fallback = Path(getattr(args, "profile_fallback_seed", "") or "").expanduser()
        if fallback and str(fallback) != ".":
            paths.append(fallback)
    if not paths:
        raise ValueError("profile collection requires --profile-seed, --profile-seed-list, or --profile-seed-dir")
    limit = int(getattr(args, "profile_seed_limit", 0) or 0)
    resolved: list[ProfileWorkload] = []
    for path in paths[:limit if limit > 0 else None]:
        require_file(path.resolve())
        resolved.append(ProfileWorkload(path.resolve(), slugify(path.stem)))
    return resolved


def target_ids_from_args(args: Any) -> list[str]:
    explicit = getattr(args, "profile_target", None) or getattr(args, "rotation_target", None) or []
    return [str(item) for item in explicit if str(item)]


def select_targets_for_profile(args: Any) -> list[SurgeTarget]:
    manifest = Path(args.target_manifest).expanduser()
    targets = load_target_manifest(manifest)
    ids = target_ids_from_args(args)
    if not ids:
        return targets
    by_id = {target.id: target for target in targets}
    missing = [target_id for target_id in ids if target_id not in by_id]
    if missing:
        raise ValueError(f"unknown SurgeFuzz profile target(s): {', '.join(missing)}")
    return [by_id[target_id] for target_id in ids]


def build_target_candidates(ctx: VcsContext, target: SurgeTarget, *, min_scope_candidates: int = 0) -> list[AncestorCandidate]:
    modules = parse_rtl_modules(ctx.build_dir / "rtl")
    module = modules.get(target.module)
    if module is None:
        raise ValueError(f"target module {target.module!r} was not found in {ctx.build_dir / 'rtl'}")
    return target_distance_candidates(module, target.signal, min_scope_candidates=min_scope_candidates)


def run_profile_for_target(args: Any, ctx: VcsContext, target: SurgeTarget) -> TargetSelection:
    target_dir = args.work_dir.expanduser().resolve() / "profile" / target.id
    target_dir.mkdir(parents=True, exist_ok=True)
    min_scope_candidates = int(getattr(args, "profile_min_scope_candidates", 64) or 0)
    candidates = build_target_candidates(ctx, target, min_scope_candidates=min_scope_candidates)
    candidates_csv = target_dir / "candidates.csv"
    write_candidate_csv(candidates_csv, candidates)

    profile_candidates, profile_subset_meta = profile_candidate_subset(
        candidates,
        max_bits=int(getattr(args, "profile_chunk_bits", 64) or 64),
        max_candidates=int(getattr(args, "profile_max_candidates", 256) or 256),
        max_candidate_width=int(getattr(args, "profile_max_candidate_width", 8) or 0),
        include_wide_candidates=bool(getattr(args, "profile_include_wide_candidates", False)),
    )
    if not profile_candidates:
        raise ValueError(
            f"target {target.id!r} has no profile candidates after filtering; "
            "raise --profile-max-candidate-width or pass --profile-include-wide-candidates"
        )
    profile_candidates_csv = target_dir / "profile_candidates.csv"
    write_candidate_csv(profile_candidates_csv, profile_candidates)

    chunks = chunk_candidates(
        profile_candidates,
        max_bits=int(getattr(args, "profile_chunk_bits", 64) or 64),
        max_candidates=0,
    )
    workloads = collect_profile_workloads(args)
    profile_rows: list[dict[str, str]] = []

    original_firrtl_cov = getattr(args, "firrtl_cov", None)
    args.firrtl_cov = "SurgeFuzz.trace"
    for chunk_index, chunk in enumerate(chunks):
        ancestor_names = [candidate.name for candidate in chunk]
        write_profile_candidate_map(target_dir / f"candidate_map_chunk_{chunk_index:03d}.csv", chunk)
        env = {
            "SFUZZ_SURGEFUZZ_MODULE": target.module,
            "SFUZZ_SURGEFUZZ_TARGET_INSTANCE": target.instance,
            "SFUZZ_SURGEFUZZ_TARGET": target.signal,
            "SFUZZ_SURGEFUZZ_ANCESTOR_SELECTOR": "manual",
            "SFUZZ_SURGEFUZZ_ANCESTORS": ",".join(ancestor_names),
            "SFUZZ_SURGEFUZZ_MAX_ANCESTOR_WIDTH": str(int(getattr(args, "profile_chunk_bits", 64) or 64)),
        }
        old_env = {key: os.environ.get(key) for key in env}
        try:
            for key, value in env.items():
                os.environ[key] = value
            build_simv_if_needed(args, ctx, target_dir)
            for workload in workloads:
                case_name = f"profile-{slugify(target.id)}-c{chunk_index:03d}-{workload.label}"
                case_dir_base = target_dir / "vcs-runs"
                logs_dir = target_dir / "logs"
                extra_env = {
                    SFUZZ_FIRRTL_COV_ENV: "SurgeFuzz.trace",
                    SFUZZ_FIRRTL_COV_OUT_ENV: str(case_dir_base / case_name / "surgefuzz_trace"),
                }
                _result, case_dir, _run_log, _assert_log = run_vcs_seed(
                    seed=workload.path,
                    case_name=case_name,
                    runs_dir=case_dir_base,
                    logs_dir=logs_dir,
                    ctx=ctx,
                    timeout_sec=args.timeout_sec,
                    cov=getattr(args, "cov", False),
                    simv_args=getattr(args, "simv_args", None),
                    extra_env=extra_env,
                )
                trace = case_dir / "surgefuzz_trace.csv"
                if trace.is_file():
                    profile_rows.extend(trace_to_named_profile_rows(trace, workload, chunk_index, chunk))
        finally:
            for key, value in old_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
    args.firrtl_cov = original_firrtl_cov

    profile_csv = target_dir / "dependents.csv"
    merge_profile_rows(profile_csv, profile_rows)
    quality = profile_candidate_quality(profile_candidates, profile_csv)
    distance_selected, distance_selection_meta = select_ancestor_names(
        candidates,
        max_bits=int(getattr(args, "max_surgefuzz_ancestor_width", 64) or 64),
        selector="distance",
        profile_csv=profile_csv,
        nmi_threshold=float(getattr(args, "profile_nmi_threshold", target.nmi_threshold) or target.nmi_threshold),
        target_column="coverage_target",
    )
    mi_selected, mi_selection_meta = select_ancestor_names(
        candidates,
        max_bits=int(getattr(args, "max_surgefuzz_ancestor_width", 64) or 64),
        selector="distance-nmi",
        profile_csv=profile_csv,
        nmi_threshold=float(getattr(args, "profile_nmi_threshold", target.nmi_threshold) or target.nmi_threshold),
        target_column="coverage_target",
    )
    use_mi = not getattr(args, "profile_no_mi", False) and bool(mi_selection_meta.get("mi_pruning_applied"))
    selected = mi_selected if use_mi else distance_selected
    selection_meta = mi_selection_meta if use_mi else distance_selection_meta
    for meta_item in (selection_meta, distance_selection_meta, mi_selection_meta):
        meta_item["profile_quality"] = quality
        meta_item["profile_candidate_subset"] = profile_subset_meta
        meta_item["profile_min_scope_candidates"] = min_scope_candidates
    selected_csv = target_dir / "selected_ancestors.csv"
    nmi_report_csv = target_dir / "nmi_report.csv"
    meta_json = target_dir / "selection_meta.json"
    write_selected_csv(selected_csv, selected, candidates)
    write_nmi_report(nmi_report_csv, candidates, profile_csv, selected)
    meta = {
        "generated_at": now_iso(),
        "target": target.__dict__,
        "candidate_count": len(candidates),
        "profile_min_scope_candidates": min_scope_candidates,
        "profile_rows": len(profile_rows),
        "profile_quality": quality,
        "profile_candidate_subset": profile_subset_meta,
        "profile_csv": str(profile_csv),
        "candidates_csv": str(candidates_csv),
        "profile_candidates_csv": str(profile_candidates_csv),
        "selected_csv": str(selected_csv),
        "nmi_report_csv": str(nmi_report_csv),
        "selection": selection_meta,
        "distance_selection": distance_selection_meta,
        "mi_selection": mi_selection_meta,
        "selected_ancestors": selected,
        "distance_selected_ancestors": distance_selected,
        "mi_selected_ancestors": mi_selected,
        "profile_chunk_count": len(chunks),
        "profile_chunk_bits": int(getattr(args, "profile_chunk_bits", 64) or 64),
        "profile_workloads": [str(workload.path) for workload in workloads],
    }
    meta_json.write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
    return TargetSelection(
        target,
        candidates,
        selected,
        distance_selected,
        mi_selected,
        selection_meta,
        distance_selection_meta,
        mi_selection_meta,
        profile_csv,
        candidates_csv,
        selected_csv,
        nmi_report_csv,
        meta_json,
    )


def write_rotation_manifest(path: Path, selections: list[TargetSelection]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "generated_at": now_iso(),
        "mode": "surgefuzz_target_rotation_extension",
        "paper_faithful": False,
        "paper_based": True,
        "extension": "target_rotation",
        "targets": [
            {
                "id": selection.target.id,
                "category": selection.target.category,
                "module": selection.target.module,
                "instance": selection.target.instance,
                "signal": selection.target.signal,
                "annotation": selection.target.annotation,
                "ancestor_selector": "distance-nmi"
                if selection.selection_meta.get("mi_pruning_applied")
                else "distance",
                "ancestor_profile": str(selection.profile_csv),
                "selected_ancestors_csv": str(selection.selected_csv),
                "selected_ancestors": selection.selected,
                "distance_selected_ancestors": selection.distance_selected,
                "mi_selected_ancestors": selection.mi_selected,
                "mi_pruning_applied": bool(selection.selection_meta.get("mi_pruning_applied")),
                "nmi_threshold": selection.target.nmi_threshold,
                "profile_quality": selection.selection_meta.get("profile_quality", {}),
                "selection_meta": str(selection.meta_json),
            }
            for selection in selections
        ],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def run_surgefuzz_profile(args: Any, ctx: VcsContext) -> int:
    if ctx.cycles is not None:
        raise ValueError("SurgeFuzz profile collection must use --no-cycle-limit and external --timeout-sec")
    if args.timeout_sec <= 0:
        raise ValueError("SurgeFuzz profile collection requires --timeout-sec")
    selections = [run_profile_for_target(args, ctx, target) for target in select_targets_for_profile(args)]
    output = args.rotation_manifest or args.work_dir.expanduser().resolve() / "surgefuzz_rotation_manifest.json"
    write_rotation_manifest(output.expanduser().resolve(), selections)
    summary = {
        "generated_at": now_iso(),
        "targets": [
            {
                "id": selection.target.id,
                "candidate_count": len(selection.candidates),
                "profile_quality": selection.selection_meta.get("profile_quality", {}),
                "selected_count": len(selection.selected),
                "distance_selected_count": len(selection.distance_selected),
                "mi_selected_count": len(selection.mi_selected),
                "profile_csv": str(selection.profile_csv),
                "selected_csv": str(selection.selected_csv),
                "mi_pruning_applied": selection.selection_meta.get("mi_pruning_applied"),
            }
            for selection in selections
        ],
        "rotation_manifest": str(output),
    }
    summary_path = args.work_dir.expanduser().resolve() / "surgefuzz_profile_summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(f"SurgeFuzz profile collection wrote {summary_path} and {output}")
    return 0
