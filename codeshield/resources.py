from __future__ import annotations

import sys
from pathlib import Path


def application_root() -> Path:
    frozen_root = getattr(sys, "_MEIPASS", None)
    if frozen_root:
        return Path(frozen_root)
    return Path(__file__).resolve().parent.parent


def resource_path(*parts: str) -> Path:
    return application_root().joinpath(*parts)


def demo_project_path() -> Path:
    candidates = []
    if getattr(sys, "frozen", False):
        executable_dir = Path(sys.executable).resolve().parent
        candidates.extend((executable_dir / "demo_project", executable_dir.parent / "demo_project"))
    candidates.append(resource_path("demo_project"))
    return next((path for path in candidates if path.is_dir()), candidates[-1])
