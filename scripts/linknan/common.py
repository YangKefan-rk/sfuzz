from __future__ import annotations

import csv
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def require_file(path: Path) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"missing required file: {path}")


def require_dir(path: Path) -> None:
    if not path.is_dir():
        raise FileNotFoundError(f"missing required directory: {path}")


def slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip())
    slug = slug.strip(".-")
    return slug or "seed"


def write_table(rows: list[dict[str, Any]], json_path: Path, csv_path: Path, fieldnames: list[str], meta: dict[str, Any]) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "generated_at": now_iso(),
        **meta,
        "results": rows,
    }
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    with csv_path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            clean = {}
            for key in fieldnames:
                value = row.get(key, "")
                if isinstance(value, list):
                    value = ";".join(str(item) for item in value)
                clean[key] = value
            writer.writerow(clean)


def append_notes(*items: Any) -> str:
    notes: list[str] = []
    for item in items:
        if item is None:
            continue
        if isinstance(item, str):
            if item:
                notes.append(item)
        elif isinstance(item, dict):
            notes.extend(f"{key}={value}" for key, value in item.items() if value not in {None, ""})
        elif isinstance(item, list):
            notes.extend(str(value) for value in item if value)
        else:
            notes.append(str(item))
    return ";".join(notes)


def popcount_bytes(data: bytes) -> int:
    return sum(byte.bit_count() for byte in data)
