from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from codeshield.version import APP_NAME, APP_VERSION


def run(command: list[str], *, env: dict[str, str] | None = None) -> None:
    subprocess.run(command, cwd=ROOT, env=env, check=True)


def remove_generated(path: Path) -> None:
    resolved = path.resolve()
    if resolved.parent != ROOT.resolve():
        raise RuntimeError(f"拒绝清理项目根目录以外的路径：{resolved}")
    if resolved.exists():
        shutil.rmtree(resolved)


def write_version_info(path: Path) -> None:
    numeric = tuple(int(part) for part in APP_VERSION.split(".")) + (0,)
    version_tuple = numeric[:4]
    content = f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={version_tuple!r}, prodvers={version_tuple!r}, mask=0x3f,
    flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[StringFileInfo([StringTable('080404b0', [
    StringStruct('CompanyName', 'CodeShield'),
    StringStruct('FileDescription', 'CodeShield 本地代码敏感信息扫描工具'),
    StringStruct('FileVersion', '{APP_VERSION}'),
    StringStruct('InternalName', '{APP_NAME}'),
    StringStruct('OriginalFilename', '{APP_NAME}.exe'),
    StringStruct('ProductName', '{APP_NAME}'),
    StringStruct('ProductVersion', '{APP_VERSION}')])]),
    VarFileInfo([VarStruct('Translation', [2052, 1200])])])
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def source_checks(python: str) -> None:
    with tempfile.TemporaryDirectory(prefix="codeshield-build-check-") as directory:
        env = os.environ.copy()
        env["LOCALAPPDATA"] = directory
        run([python, "-m", "pytest", "-q"], env=env)
        run([python, "-m", "compileall", "-q", "main.py", "codeshield", "tests"], env=env)
        run([python, "main.py", "--check"], env=env)


def build(skip_checks: bool = False) -> Path:
    python = sys.executable
    if not skip_checks:
        source_checks(python)
    for name in ("build", "dist", "release"):
        remove_generated(ROOT / name)
    write_version_info(ROOT / "build" / "version_info.txt")
    run([python, "-m", "PyInstaller", "--noconfirm", "--clean", "CodeShield.spec"])

    dist_app = ROOT / "dist" / APP_NAME
    executable = dist_app / f"{APP_NAME}.exe"
    if not executable.is_file():
        raise RuntimeError(f"PyInstaller 未生成预期文件：{executable}")
    release_root = ROOT / "release" / f"{APP_NAME}-{APP_VERSION}"
    shutil.copytree(dist_app, release_root / APP_NAME)
    shutil.copytree(
        ROOT / "demo_project",
        release_root / "demo_project",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "tests"),
    )
    print(f"发布目录：{release_root}")
    return release_root


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="构建 CodeShield Windows onedir 发布目录")
    parser.add_argument("--skip-checks", action="store_true", help="跳过已单独完成的源码检查")
    arguments = parser.parse_args()
    build(arguments.skip_checks)
