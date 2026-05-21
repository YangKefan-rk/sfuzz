from __future__ import annotations

from typing import Any

from ..config import VcsContext


def run_profuzz(_args: Any, _ctx: VcsContext) -> int:
    raise SystemExit(
        "PROFUZZ 的 LinkNan/VCS 入口已预留；当前必须先接入论文定义的目标点覆盖/反馈 ABI，"
        "不能用 VCS log、mock 或普通覆盖替代 paper-faithful PROFUZZ 数据。"
    )
