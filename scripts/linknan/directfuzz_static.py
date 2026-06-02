from __future__ import annotations

import csv
import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path


MODULE_RE = re.compile(r"\bmodule\s+([A-Za-z_][A-Za-z0-9_$]*)\s*\((.*?)^\);\s*$", re.S | re.M)
INSTANCE_LINE_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_$]*)\s+(?:#\s*\(.*?\)\s*)?([A-Za-z_][A-Za-z0-9_$]*)\s*\("
)
ASSIGN_RE = re.compile(
    r"^\s*(?:(wire|logic)\s+(?:(?:signed|unsigned)\s+)?(?:\[[^\]]+\]\s*)*)?"
    r"(?:assign\s+)?"
    r"([A-Za-z_][A-Za-z0-9_$]*(?:\[[^\]]+\])?)\s*=\s*(.*);\s*$",
    re.S,
)

SKIP_INSTANCE_TYPES = {
    "LogPerfHelper",
    "DifftestMem1P",
    "DifftestFlash",
    "DifftestEndpoint",
}


@dataclass
class ModuleDef:
    name: str
    body: str
    mux_count: int
    children: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class InstanceNode:
    path: str
    module: str
    parent: str
    mux_count: int


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//.*", "", text)


def statement_spans(body: str):
    start = 0
    depth = 0
    for i, ch in enumerate(body):
        if ch in "([{":
            depth += 1
        elif ch in ")]}" and depth > 0:
            depth -= 1
        elif ch == ";" and depth == 0:
            stmt = body[start : i + 1].strip()
            if stmt:
                yield stmt
            start = i + 1


def top_level_question(expr: str) -> int:
    paren = bracket = brace = 0
    for i, ch in enumerate(expr):
        if ch == "(":
            paren += 1
        elif ch == ")" and paren > 0:
            paren -= 1
        elif ch == "[":
            bracket += 1
        elif ch == "]" and bracket > 0:
            bracket -= 1
        elif ch == "{":
            brace += 1
        elif ch == "}" and brace > 0:
            brace -= 1
        elif ch == "?" and paren == 0 and bracket == 0 and brace == 0:
            return i
    return -1


def count_muxes(body: str) -> int:
    count = 0
    for stmt in statement_spans(body):
        if "?" not in stmt:
            continue
        match = ASSIGN_RE.match(stmt)
        if match is None:
            continue
        rhs = re.sub(r"\s+", " ", match.group(3).strip())
        cond_pos = top_level_question(rhs)
        if cond_pos >= 0 and rhs[:cond_pos].strip():
            count += 1
    return count


def parse_modules(rtl_dir: Path) -> dict[str, ModuleDef]:
    modules: dict[str, ModuleDef] = {}
    for file in sorted(rtl_dir.glob("*.sv")):
        text = strip_comments(file.read_text(encoding="utf-8", errors="replace"))
        for match in MODULE_RE.finditer(text):
            name = match.group(1)
            body_start = match.start()
            next_module = text.find("\nmodule ", match.end())
            body_end = len(text) if next_module < 0 else next_module
            body = text[body_start:body_end]
            modules[name] = ModuleDef(name=name, body=body, mux_count=count_muxes(body))

    known = set(modules)
    for module in modules.values():
        for line in module.body.splitlines():
            match = INSTANCE_LINE_RE.match(line)
            if match is None:
                continue
            child_type, child_name = match.groups()
            if child_type in known and child_type not in SKIP_INSTANCE_TYPES:
                module.children.append((child_name, child_type))
    return modules


def build_instance_tree(modules: dict[str, ModuleDef], top_module: str) -> dict[str, InstanceNode]:
    if top_module not in modules:
        raise ValueError(f"top module {top_module!r} is not present in generated RTL")
    nodes: dict[str, InstanceNode] = {}

    def visit(path: str, module_name: str, parent: str) -> None:
        if path in nodes:
            return
        module = modules[module_name]
        nodes[path] = InstanceNode(path=path, module=module_name, parent=parent, mux_count=module.mux_count)
        for child_name, child_type in module.children:
            visit(f"{path}.{child_name}", child_type, path)

    visit(top_module, top_module, "")
    return nodes


def distance_map(nodes: dict[str, InstanceNode], target_instance: str) -> dict[str, int | None]:
    if target_instance not in nodes:
        raise ValueError(f"target instance {target_instance!r} is not present in parsed RTL instance tree")
    graph: dict[str, set[str]] = {name: set() for name in nodes}
    children_by_parent: dict[str, list[str]] = {}
    for name, node in nodes.items():
        if node.parent:
            graph[name].add(node.parent)
            graph[node.parent].add(name)
            children_by_parent.setdefault(node.parent, []).append(name)
    for siblings in children_by_parent.values():
        for idx, left in enumerate(siblings):
            for right in siblings[idx + 1 :]:
                graph[left].add(right)
                graph[right].add(left)

    distances: dict[str, int | None] = {name: None for name in nodes}
    distances[target_instance] = 0
    queue: deque[str] = deque([target_instance])
    while queue:
        current = queue.popleft()
        current_distance = distances[current]
        assert current_distance is not None
        for nxt in sorted(graph[current]):
            if distances[nxt] is None:
                distances[nxt] = current_distance + 1
                queue.append(nxt)
    return distances


def write_metadata(rtl_dir: Path, output: Path, target_instance: str, top_module: str = "SimTop") -> None:
    modules = parse_modules(rtl_dir)
    nodes = build_instance_tree(modules, top_module)
    distances = distance_map(nodes, target_instance)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=["instance_name", "coverage_signal_name", "width", "distance"])
        writer.writeheader()
        for name in sorted(nodes):
            node = nodes[name]
            if node.mux_count <= 0:
                continue
            distance = distances[name]
            writer.writerow(
                {
                    "instance_name": name,
                    "coverage_signal_name": f"coverage_{node.module}",
                    "width": node.mux_count,
                    "distance": "256" if distance is None else str(distance),
                }
            )
