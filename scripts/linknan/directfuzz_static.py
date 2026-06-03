from __future__ import annotations

import csv
import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path


MODULE_RE = re.compile(r"\bmodule\s+([A-Za-z_][A-Za-z0-9_$]*)\s*\((.*?)^\);\s*$", re.S | re.M)
DECL_RE = re.compile(
    r"^\s*(input|output|inout|wire|reg|logic)\s+"
    r"(?:(?:wire|reg|logic|signed|unsigned)\s+)*"
    r"((?:\[[^\]]+\]\s*)*)"
    r"([A-Za-z_][A-Za-z0-9_$]*)\s*(?:[,;=)]|$)"
)
ASSIGN_RE = re.compile(
    r"^\s*(?:(wire|logic)\s+(?:(?:signed|unsigned)\s+)?(?:\[[^\]]+\]\s*)*)?"
    r"(?:assign\s+)?"
    r"([A-Za-z_][A-Za-z0-9_$]*(?:\[[^\]]+\])?)\s*=\s*(.*);\s*$",
    re.S,
)
INSTANCE_START_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_$]*)\s+"
    r"(?:#\s*\(.*\)\s*)?"
    r"([A-Za-z_][A-Za-z0-9_$]*)\s*\(",
)
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*")
SV_KEYWORDS = {
    "assign",
    "begin",
    "case",
    "default",
    "else",
    "end",
    "endcase",
    "endmodule",
    "for",
    "generate",
    "if",
    "inout",
    "input",
    "logic",
    "module",
    "output",
    "parameter",
    "reg",
    "signed",
    "wire",
}


@dataclass(frozen=True)
class Signal:
    name: str
    width: int
    direction: str


@dataclass(frozen=True)
class ChildInstance:
    name: str
    module: str
    connections: dict[str, str]


@dataclass
class ModuleDef:
    name: str
    body: str
    inputs: dict[str, Signal]
    signals: dict[str, Signal]
    children: list[ChildInstance] = field(default_factory=list)
    mux_count: int = 0

    @property
    def bindable(self) -> bool:
        return bool(choose_clock(self.inputs) and choose_reset(self.inputs))


@dataclass(frozen=True)
class InstanceNode:
    path: str
    module: str
    parent: str


@dataclass(frozen=True)
class GraphEdge:
    src: str
    dst: str
    kind: str
    detail: str


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//.*", "", text)


def width_from_dims(dims: str) -> int:
    width = 1
    for msb, lsb in re.findall(r"\[\s*(\d+)\s*:\s*(\d+)\s*\]", dims):
        width *= abs(int(msb) - int(lsb)) + 1
    return width


def choose_clock(inputs: dict[str, Signal]) -> str:
    for name in ("clock", "clk"):
        sig = inputs.get(name)
        if sig and sig.width == 1:
            return name
    for name, sig in sorted(inputs.items()):
        lower = name.lower()
        if sig.width == 1 and (lower.endswith("clock") or lower.endswith("clk")):
            return name
    return ""


def choose_reset(inputs: dict[str, Signal]) -> str:
    for name in ("reset", "rst"):
        sig = inputs.get(name)
        if sig and sig.width == 1:
            return name
    for name, sig in sorted(inputs.items()):
        lower = name.lower()
        if sig.width == 1 and (lower.endswith("reset") or lower.endswith("rst")) and not lower.endswith("_n"):
            return name
    return ""


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
        cond = rhs[:cond_pos].strip() if cond_pos >= 0 else ""
        if cond and len(cond) <= 512:
            count += 1
    return count


def find_matching_paren(text: str, open_idx: int) -> int:
    depth = 0
    for idx in range(open_idx, len(text)):
        ch = text[idx]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return idx
    return -1


def parse_named_connections(text: str) -> dict[str, str]:
    conns: dict[str, str] = {}
    idx = 0
    while idx < len(text):
        dot = text.find(".", idx)
        if dot < 0:
            break
        name_match = IDENT_RE.match(text, dot + 1)
        if name_match is None:
            idx = dot + 1
            continue
        port = name_match.group(0)
        pos = name_match.end()
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text) or text[pos] != "(":
            idx = pos
            continue
        end = find_matching_paren(text, pos)
        if end < 0:
            break
        conns[port] = text[pos + 1 : end].strip()
        idx = end + 1
    return conns


def parse_child_instances(module: ModuleDef, known_modules: set[str]) -> list[ChildInstance]:
    children: list[ChildInstance] = []
    lines = module.body.splitlines()
    idx = 0
    while idx < len(lines):
        match = INSTANCE_START_RE.match(lines[idx])
        if match is None:
            idx += 1
            continue
        child_module, child_name = match.groups()
        if child_module not in known_modules:
            idx += 1
            continue
        stmt_lines = [lines[idx]]
        idx += 1
        while idx < len(lines) and not re.search(r"\)\s*;\s*$", lines[idx]):
            stmt_lines.append(lines[idx])
            idx += 1
        if idx < len(lines):
            stmt_lines.append(lines[idx])
            idx += 1
        stmt = "\n".join(stmt_lines)
        open_idx = stmt.find("(", stmt.find(child_name) + len(child_name))
        close_idx = find_matching_paren(stmt, open_idx) if open_idx >= 0 else -1
        ports = stmt[open_idx + 1 : close_idx] if close_idx >= 0 else ""
        children.append(ChildInstance(child_name, child_module, parse_named_connections(ports)))
    return children


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
            inputs: dict[str, Signal] = {}
            signals: dict[str, Signal] = {}
            for line in body.splitlines():
                decl = DECL_RE.match(line)
                if decl is None:
                    continue
                kind, dims, sig_name = decl.groups()
                signal = Signal(sig_name, width_from_dims(dims), kind)
                signals.setdefault(sig_name, signal)
                if kind == "input":
                    inputs[sig_name] = signal
            modules[name] = ModuleDef(name=name, body=body, inputs=inputs, signals=signals, mux_count=count_muxes(body))

    known = set(modules)
    for module in modules.values():
        module.children = parse_child_instances(module, known)
    return modules


def selected_mux_counts(modules: dict[str, ModuleDef], limit: int) -> dict[str, int]:
    remaining = (1 << 62) if limit <= 0 else limit
    counts: dict[str, int] = {}
    for module in modules.values():
        if not module.bindable:
            continue
        if remaining <= 0:
            break
        selected = min(module.mux_count, remaining)
        if selected > 0:
            counts[module.name] = selected
            remaining -= selected
    return counts


def build_instance_tree(modules: dict[str, ModuleDef], top_module: str) -> dict[str, InstanceNode]:
    if top_module not in modules:
        raise ValueError(f"top module {top_module!r} is not present in generated RTL")
    nodes: dict[str, InstanceNode] = {}

    def visit(path: str, module_name: str, parent: str) -> None:
        if path in nodes:
            return
        nodes[path] = InstanceNode(path=path, module=module_name, parent=parent)
        module = modules[module_name]
        for child in module.children:
            visit(f"{path}.{child.name}", child.module, path)

    visit(top_module, top_module, "")
    return nodes


def base_signal(name: str) -> str:
    return name.split("[", 1)[0].strip()


def identifiers(text: str) -> set[str]:
    result: set[str] = set()
    for match in IDENT_RE.finditer(text):
        name = match.group(0)
        if name.lower() in SV_KEYWORDS:
            continue
        if match.start() > 0 and text[match.start() - 1] == "'":
            continue
        result.add(name)
    return result


def assignment_edges(module: ModuleDef) -> dict[str, set[str]]:
    edges: dict[str, set[str]] = {}
    for stmt in statement_spans(module.body):
        match = ASSIGN_RE.match(stmt)
        if match is None:
            continue
        lhs = base_signal(match.group(2))
        rhs_ids = identifiers(match.group(3))
        for rhs in rhs_ids:
            if rhs != lhs:
                edges.setdefault(rhs, set()).add(lhs)
    return edges


def reachable_nets(start: str, edges: dict[str, set[str]], memo: dict[str, set[str]]) -> set[str]:
    if start in memo:
        return memo[start]
    seen = {start}
    queue: deque[str] = deque([start])
    while queue:
        current = queue.popleft()
        for nxt in edges.get(current, set()):
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    memo[start] = seen
    return seen


def build_directed_connectivity_graph(
    modules: dict[str, ModuleDef],
    nodes: dict[str, InstanceNode],
) -> tuple[dict[str, set[str]], list[GraphEdge]]:
    graph: dict[str, set[str]] = {path: set() for path in nodes}
    edges: list[GraphEdge] = []
    edge_keys: set[tuple[str, str, str, str]] = set()

    def add_edge(src: str, dst: str, kind: str, detail: str) -> None:
        if src == dst or src not in graph or dst not in graph:
            return
        edge_key = (src, dst, kind, detail)
        if edge_key not in edge_keys:
            edges.append(GraphEdge(src, dst, kind, detail))
            edge_keys.add(edge_key)
        graph[src].add(dst)

    for path, node in nodes.items():
        module = modules[node.module]
        child_by_name = {child.name: child for child in module.children}

        for child in module.children:
            child_path = f"{path}.{child.name}"
            if child_path in graph:
                add_edge(path, child_path, "structural_child", f"{node.module}.{child.name}:{child.module}")

        drivers: dict[str, set[str]] = {}
        consumers: dict[str, set[str]] = {}
        for sig in module.signals.values():
            if sig.direction == "input":
                drivers.setdefault(sig.name, set()).add(path)
            elif sig.direction == "output":
                consumers.setdefault(sig.name, set()).add(path)
            elif sig.direction == "inout":
                drivers.setdefault(sig.name, set()).add(path)
                consumers.setdefault(sig.name, set()).add(path)

        for child_name, child in child_by_name.items():
            child_path = f"{path}.{child_name}"
            if child_path not in graph:
                continue
            child_module = modules[child.module]
            for port, expr in child.connections.items():
                port_sig = child_module.signals.get(port)
                if port_sig is None:
                    continue
                nets = identifiers(expr)
                if not nets:
                    continue
                if port_sig.direction == "input":
                    for net in nets:
                        consumers.setdefault(net, set()).add(child_path)
                elif port_sig.direction == "output":
                    for net in nets:
                        drivers.setdefault(net, set()).add(child_path)
                elif port_sig.direction == "inout":
                    for net in nets:
                        drivers.setdefault(net, set()).add(child_path)
                        consumers.setdefault(net, set()).add(child_path)

        net_edges = assignment_edges(module)
        memo: dict[str, set[str]] = {}
        for net, source_nodes in drivers.items():
            downstream_nets = reachable_nets(net, net_edges, memo)
            for downstream_net in downstream_nets:
                for src in source_nodes:
                    for dst in consumers.get(downstream_net, set()):
                        add_edge(src, dst, "signal_direction", f"{path}:{net}->{downstream_net}")
    return graph, edges


def distance_map(
    graph: dict[str, set[str]],
    target_instance: str,
) -> tuple[dict[str, int | None], dict[str, str]]:
    if target_instance not in graph:
        raise ValueError(f"target instance {target_instance!r} is not present in parsed RTL instance tree")
    reverse: dict[str, set[str]] = {node: set() for node in graph}
    for src, dsts in graph.items():
        for dst in dsts:
            if dst in reverse:
                reverse[dst].add(src)

    distances: dict[str, int | None] = {node: None for node in graph}
    predecessors: dict[str, str] = {}
    distances[target_instance] = 0
    queue: deque[str] = deque([target_instance])
    while queue:
        current = queue.popleft()
        current_distance = distances[current]
        assert current_distance is not None
        for prev in sorted(reverse[current]):
            if distances[prev] is None:
                distances[prev] = current_distance + 1
                predecessors[prev] = current
                queue.append(prev)
    return distances, predecessors


def write_graph_artifacts(
    output_dir: Path,
    *,
    target_instance: str,
    nodes: dict[str, InstanceNode],
    mux_counts: dict[str, int],
    graph: dict[str, set[str]],
    edges: list[GraphEdge],
    distances: dict[str, int | None],
    predecessors: dict[str, str],
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    edges_path = output_dir / "directfuzz_instance_edges.csv"
    with edges_path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=["src_instance", "dst_instance", "kind", "detail"])
        writer.writeheader()
        for edge in sorted(edges, key=lambda e: (e.src, e.dst, e.kind, e.detail)):
            writer.writerow(
                {
                    "src_instance": edge.src,
                    "dst_instance": edge.dst,
                    "kind": edge.kind,
                    "detail": edge.detail,
                }
            )

    distances_path = output_dir / "directfuzz_instance_distances.csv"
    with distances_path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=[
                "instance_name",
                "module_name",
                "width",
                "distance",
                "next_hop_to_target",
                "out_degree",
                "in_degree",
            ],
        )
        writer.writeheader()
        in_degree: dict[str, int] = {name: 0 for name in nodes}
        for dsts in graph.values():
            for dst in dsts:
                if dst in in_degree:
                    in_degree[dst] += 1
        for name in sorted(nodes):
            node = nodes[name]
            distance = distances[name]
            writer.writerow(
                {
                    "instance_name": name,
                    "module_name": node.module,
                    "width": mux_counts.get(node.module, 0),
                    "distance": "undefined" if distance is None else str(distance),
                    "next_hop_to_target": predecessors.get(name, ""),
                    "out_degree": len(graph.get(name, set())),
                    "in_degree": in_degree.get(name, 0),
                }
            )

    summary_path = output_dir / "directfuzz_instance_graph_summary.csv"
    reachable = sum(1 for value in distances.values() if value is not None)
    coverage_instances = sum(1 for node in nodes.values() if mux_counts.get(node.module, 0) > 0)
    with summary_path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=["key", "value"])
        writer.writeheader()
        writer.writerows(
            [
                {"key": "target_instance", "value": target_instance},
                {"key": "instances_total", "value": str(len(nodes))},
                {"key": "coverage_instances", "value": str(coverage_instances)},
                {"key": "edges_total", "value": str(len(edges))},
                {
                    "key": "signal_direction_edges",
                    "value": str(sum(1 for edge in edges if edge.kind == "signal_direction")),
                },
                {
                    "key": "structural_child_edges",
                    "value": str(sum(1 for edge in edges if edge.kind == "structural_child")),
                },
                {"key": "reachable_instances", "value": str(reachable)},
                {"key": "unreachable_instances", "value": str(len(nodes) - reachable)},
            ]
        )


def write_metadata(
    rtl_dir: Path,
    output: Path,
    target_instance: str,
    top_module: str = "SimTop",
    max_mux: int = 0,
    graph_output_dir: Path | None = None,
) -> None:
    modules = parse_modules(rtl_dir)
    nodes = build_instance_tree(modules, top_module)
    mux_counts = selected_mux_counts(modules, max_mux)
    graph, edges = build_directed_connectivity_graph(modules, nodes)
    distances, predecessors = distance_map(graph, target_instance)
    if graph_output_dir is not None:
        write_graph_artifacts(
            graph_output_dir,
            target_instance=target_instance,
            nodes=nodes,
            mux_counts=mux_counts,
            graph=graph,
            edges=edges,
            distances=distances,
            predecessors=predecessors,
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=["instance_name", "coverage_signal_name", "width", "distance"])
        writer.writeheader()
        for name in sorted(nodes):
            node = nodes[name]
            width = mux_counts.get(node.module, 0)
            if width <= 0:
                continue
            distance = distances[name]
            writer.writerow(
                {
                    "instance_name": name,
                    "coverage_signal_name": f"coverage_{node.module}",
                    "width": str(width),
                    "distance": "undefined" if distance is None else str(distance),
                }
            )
