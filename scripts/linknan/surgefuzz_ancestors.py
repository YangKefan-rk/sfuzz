from __future__ import annotations

import csv
import math
import re
from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path


IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_$]*\b")
ASSIGN_RE = re.compile(
    r"^\s*(?:(?:wire|logic|reg)\s+(?:(?:signed|unsigned)\s+)?(?:\[[^\]]+\]\s*)*)?"
    r"(?:assign\s+)?([A-Za-z_][A-Za-z0-9_$]*(?:\[[^\]]+\])?)\s*=\s*(.*);\s*$",
    re.S,
)


@dataclass(frozen=True)
class AncestorCandidate:
    name: str
    width: int
    direction: str
    depth: int
    register_depth: int
    is_control: bool
    source: str


def statement_spans(body: str) -> list[str]:
    statements: list[str] = []
    start = 0
    depth = 0
    for index, char in enumerate(body):
        if char in "([{":
            depth += 1
        elif char in ")]}" and depth > 0:
            depth -= 1
        elif char == ";" and depth == 0:
            statement = body[start : index + 1].strip()
            if statement:
                statements.append(statement)
            start = index + 1
    return statements


def identifiers(text: str) -> set[str]:
    ignored = {
        "assign",
        "wire",
        "logic",
        "reg",
        "signed",
        "unsigned",
        "input",
        "output",
        "inout",
        "if",
        "else",
        "begin",
        "end",
        "case",
        "endcase",
    }
    return {item for item in IDENT_RE.findall(text) if item not in ignored and not re.fullmatch(r"\d+'[hdb][0-9a-fA-F_xXzZ]+", item)}


def base_name(name: str) -> str:
    return name.split("[", 1)[0]


def build_dependency_graph(module: object) -> dict[str, set[str]]:
    graph: dict[str, set[str]] = {}
    signal_names = set(getattr(module, "signals", {}))
    for statement in statement_spans(getattr(module, "body", "")):
        match = ASSIGN_RE.match(statement)
        if match is None:
            continue
        lhs = base_name(match.group(1))
        rhs = match.group(2)
        deps = {name for name in identifiers(rhs) if name in signal_names and name != lhs}
        if deps:
            graph.setdefault(lhs, set()).update(deps)
    return graph


def is_control_signal(name: str) -> bool:
    lower = name.lower()
    return any(
        keyword in lower
        for keyword in (
            "valid",
            "ready",
            "fire",
            "miss",
            "replay",
            "stall",
            "flush",
            "nack",
            "conflict",
            "block",
            "full",
            "kill",
            "cancel",
        )
    )


def target_tokens(name: str) -> list[str]:
    tokens = [token for token in re.split(r"[_$]+", base_name(name).lower()) if len(token) >= 3]
    return [token for token in tokens if token not in {"info", "monitor", "pipe", "vec", "req"}]


def register_depth(direction: str) -> int:
    return 0 if direction in {"input", "output", "wire"} else 1


def target_scope_candidates(
    module: object,
    target: str,
    *,
    exclude: set[str] | None = None,
    min_score: int = 1,
    depth: int = 90,
) -> list[AncestorCandidate]:
    signals: dict[str, object] = getattr(module, "signals", {})
    target_name = base_name(target)
    tokens = target_tokens(target_name)
    excluded = set(exclude or ())
    candidates: list[tuple[int, AncestorCandidate]] = []
    for name, signal in signals.items():
        direction = str(getattr(signal, "direction", ""))
        width = int(getattr(signal, "width", 1))
        if name == target_name or name in excluded or width <= 0 or direction == "inout":
            continue
        lower = name.lower()
        token_hits = sum(1 for token in tokens if token in lower)
        control = is_control_signal(name)
        reg_depth = register_depth(direction)
        score = token_hits + (2 if control else 0) + (1 if reg_depth > 0 else 0)
        if score < min_score:
            continue
        candidates.append(
            (
                -score,
                AncestorCandidate(
                    name,
                    width,
                    direction,
                    depth,
                    reg_depth,
                    control,
                    f"target-scope:{target_name}:score={score}:tokens={token_hits}",
                ),
            )
        )
    return [candidate for _score, candidate in sorted(candidates, key=lambda item: (item[0], item[1].register_depth, item[1].width, item[1].name))]


def extend_target_specific_candidates(
    module: object,
    target: str,
    candidates: list[AncestorCandidate],
    *,
    min_count: int = 64,
) -> list[AncestorCandidate]:
    if len(candidates) >= min_count:
        return candidates
    seen = {candidate.name for candidate in candidates}
    scoped = target_scope_candidates(module, target, exclude=seen, min_score=1)
    return [*candidates, *scoped[: max(0, min_count - len(candidates))]]


def target_distance_candidates(module: object, target: str, *, min_scope_candidates: int = 0) -> list[AncestorCandidate]:
    graph = build_dependency_graph(module)
    signals: dict[str, object] = getattr(module, "signals", {})
    target_name = base_name(target)
    seen = {target_name}
    queue: deque[tuple[str, int]] = deque([(target_name, 0)])
    candidates: list[AncestorCandidate] = []
    while queue:
        current, depth = queue.popleft()
        for dep in sorted(graph.get(current, set())):
            if dep in seen:
                continue
            seen.add(dep)
            signal = signals.get(dep)
            if signal is not None:
                direction = str(getattr(signal, "direction", ""))
                width = int(getattr(signal, "width", 1))
                if width > 0 and direction != "inout":
                    candidates.append(
                        AncestorCandidate(
                            dep,
                            width,
                            direction,
                            depth + 1,
                            register_depth(direction),
                            is_control_signal(dep),
                            f"distance:{target_name}:{depth + 1}",
                        )
                    )
            queue.append((dep, depth + 1))
    if candidates:
        return extend_target_specific_candidates(module, target, candidates, min_count=min_scope_candidates) if min_scope_candidates > 0 else candidates

    return target_scope_candidates(module, target, min_score=1, depth=99)


def sort_candidates(candidates: list[AncestorCandidate]) -> list[AncestorCandidate]:
    return sorted(candidates, key=lambda item: (item.register_depth, item.depth, not item.is_control, item.width, item.name))


def read_profile_samples(path: Path) -> dict[str, list[int]]:
    samples: dict[str, list[int]] = {}
    with path.open(newline="", encoding="utf-8") as input_file:
        reader = csv.DictReader(input_file)
        for row in reader:
            for key, value in row.items():
                if key == "cycle" or value in {None, ""}:
                    continue
                try:
                    samples.setdefault(key, []).append(int(value, 0))
                except ValueError:
                    continue
    return samples


def paired_profile_samples(path: Path, lhs: str, rhs: str) -> tuple[list[int], list[int]]:
    lhs_values: list[int] = []
    rhs_values: list[int] = []
    with path.open(newline="", encoding="utf-8") as input_file:
        reader = csv.DictReader(input_file)
        for row in reader:
            lhs_raw = row.get(lhs)
            rhs_raw = row.get(rhs)
            if lhs_raw in {None, ""} or rhs_raw in {None, ""}:
                continue
            try:
                lhs_values.append(int(lhs_raw, 0))
                rhs_values.append(int(rhs_raw, 0))
            except ValueError:
                continue
    return lhs_values, rhs_values


def entropy(values: list[int]) -> float:
    if not values:
        return 0.0
    total = len(values)
    counts = Counter(values)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def normalized_mutual_information(x_values: list[int], y_values: list[int]) -> float:
    size = min(len(x_values), len(y_values))
    if size == 0:
        return 0.0
    x = x_values[:size]
    y = y_values[:size]
    hx = entropy(x)
    hy = entropy(y)
    if hx == 0.0 and hy == 0.0:
        return 1.0 if x == y else 0.0
    xy_counts = Counter(zip(x, y))
    x_counts = Counter(x)
    y_counts = Counter(y)
    total = float(size)
    mi = 0.0
    for (xv, yv), count in xy_counts.items():
        pxy = count / total
        px = x_counts[xv] / total
        py = y_counts[yv] / total
        mi += pxy * math.log2(pxy / (px * py))
    return 2.0 * mi / (hx + hy)


def signal_name_for_profile(name: str) -> str:
    return re.sub(r"\[[^\]]+\]", "", name)


def select_ancestor_names(
    candidates: list[AncestorCandidate],
    *,
    max_bits: int,
    selector: str = "distance",
    profile_csv: Path | None = None,
    nmi_threshold: float = 0.85,
    target_column: str = "coverage_target",
) -> tuple[list[str], dict[str, object]]:
    ordered = sort_candidates(candidates)
    samples = read_profile_samples(profile_csv) if profile_csv and profile_csv.is_file() else {}
    use_mi = selector in {"distance-nmi", "distance_nmi", "nmi"} and bool(samples)
    selected: list[str] = []
    rejected: list[dict[str, object]] = []
    selected_records: list[dict[str, object]] = []
    used_bits = 0
    reference_name = target_column if target_column in samples else ""

    for candidate in ordered:
        if used_bits >= max_bits:
            break
        name = signal_name_for_profile(candidate.name)
        nmi: float | None = None
        reference_for_candidate = reference_name
        if use_mi:
            candidate_samples = samples.get(name)
            reference_samples = samples.get(reference_for_candidate) if reference_for_candidate else None
            if not candidate_samples:
                rejected.append({"name": candidate.name, "reason": "missing_profile_samples"})
                continue
            if reference_samples:
                if profile_csv is not None:
                    candidate_samples, reference_samples = paired_profile_samples(profile_csv, name, reference_for_candidate)
                nmi = normalized_mutual_information(candidate_samples, reference_samples)
                if nmi > nmi_threshold:
                    rejected.append(
                        {
                            "name": candidate.name,
                            "reason": "nmi",
                            "reference": reference_for_candidate,
                            "nmi": round(nmi, 6),
                            "samples": min(len(candidate_samples), len(reference_samples)),
                        }
                    )
                    continue

        remaining = max_bits - used_bits
        selected_name = candidate.name
        selected_width = candidate.width
        if candidate.width <= remaining:
            selected.append(selected_name)
            used_bits += candidate.width
        else:
            selected_name = f"{candidate.name}[{remaining - 1}:0]" if remaining > 1 else f"{candidate.name}[0]"
            selected_width = remaining
            selected.append(selected_name)
            used_bits += remaining
        selected_records.append(
            {
                "name": selected_name,
                "base_name": candidate.name,
                "width": selected_width,
                "depth": candidate.depth,
                "register_depth": candidate.register_depth,
                "is_control": candidate.is_control,
                "source": candidate.source,
                "reference": reference_for_candidate,
                "nmi": round(nmi, 6) if nmi is not None else None,
            }
        )
        if use_mi:
            reference_name = name

    rejected_by_reason = dict(Counter(str(item.get("reason", "")) for item in rejected))
    meta = {
        "selector": selector,
        "candidate_count": len(candidates),
        "selected_count": len(selected),
        "selected_width": used_bits,
        "profile_csv": str(profile_csv) if profile_csv else "",
        "mi_pruning_applied": use_mi,
        "nmi_threshold": nmi_threshold,
        "profile_column_count": len(samples),
        "selected": selected_records,
        "rejected_count": len(rejected),
        "rejected_by_reason": rejected_by_reason,
        "rejected": rejected[:64],
    }
    return selected, meta
