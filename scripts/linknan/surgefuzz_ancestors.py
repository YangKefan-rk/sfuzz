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


def register_depth(direction: str) -> int:
    return 0 if direction in {"input", "output", "wire"} else 1


def target_distance_candidates(module: object, target: str) -> list[AncestorCandidate]:
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
        return candidates

    fallback: list[AncestorCandidate] = []
    target_words = [word for word in re.split(r"[_$]+", target_name.lower()) if len(word) >= 3]
    for name, signal in signals.items():
        direction = str(getattr(signal, "direction", ""))
        width = int(getattr(signal, "width", 1))
        if name == target_name or width <= 0 or direction == "inout":
            continue
        lower = name.lower()
        if is_control_signal(name) or any(word in lower for word in target_words):
            fallback.append(
                AncestorCandidate(
                    name,
                    width,
                    direction,
                    99,
                    register_depth(direction),
                    is_control_signal(name),
                    f"fallback-name:{target_name}",
                )
            )
    return fallback


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
    used_bits = 0
    reference_name = target_column if target_column in samples else ""

    for candidate in ordered:
        if used_bits >= max_bits:
            break
        name = signal_name_for_profile(candidate.name)
        if use_mi:
            candidate_samples = samples.get(name)
            reference_samples = samples.get(reference_name) if reference_name else None
            if not candidate_samples:
                rejected.append({"name": candidate.name, "reason": "missing_profile_samples"})
                continue
            if reference_samples:
                if profile_csv is not None:
                    candidate_samples, reference_samples = paired_profile_samples(profile_csv, name, reference_name)
                nmi = normalized_mutual_information(candidate_samples, reference_samples)
                if nmi > nmi_threshold:
                    rejected.append({"name": candidate.name, "reason": "nmi", "nmi": round(nmi, 6)})
                    continue

        remaining = max_bits - used_bits
        if candidate.width <= remaining:
            selected.append(candidate.name)
            used_bits += candidate.width
        else:
            selected.append(f"{candidate.name}[{remaining - 1}:0]" if remaining > 1 else f"{candidate.name}[0]")
            used_bits += remaining
        if use_mi:
            reference_name = name

    meta = {
        "selector": selector,
        "candidate_count": len(candidates),
        "selected_count": len(selected),
        "selected_width": used_bits,
        "profile_csv": str(profile_csv) if profile_csv else "",
        "mi_pruning_applied": use_mi,
        "nmi_threshold": nmi_threshold,
        "rejected": rejected[:64],
    }
    return selected, meta
