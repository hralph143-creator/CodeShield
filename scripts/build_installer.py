from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from codeshield.version import APP_NAME, APP_VERSION


INNO_CANDIDATES = (
    Path.home() / "AppData/Local/Programs/Inno Setup 6/ISCC.exe",
    Path("C:/Program Files (x86)/Inno Setup 6/ISCC.exe"),
    Path("C:/Program Files/Inno Setup 6/ISCC.exe"),
    Path.home() / "AppData/Local/Programs/Inno Setup 7/ISCC.exe",
    Path("C:/Program Files/Inno Setup 7/ISCC.exe"),
)


def find_compiler(explicit: str | None = None) -> Path:
    candidates = (Path(explicit),) if explicit else INNO_CANDIDATES
    compiler = next((path for path in candidates if _is_file(path)), None)
    if compiler is None:
        raise FileNotFoundError("未找到 Inno Setup ISCC.exe，请安装官方 Inno Setup")
    return compiler


def _is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def build_installer(compiler: Path) -> Path:
    release_root = ROOT / "release" / f"{APP_NAME}-{APP_VERSION}"
    executable = release_root / APP_NAME / f"{APP_NAME}.exe"
    if not executable.is_file():
        raise FileNotFoundError(f"请先构建发布目录：{executable}")
    command = [
        str(compiler),
        f"/DAppVersion={APP_VERSION}",
        f"/DSourceDir={release_root}",
        str(ROOT / "installer" / "CodeShield.iss"),
    ]
    subprocess.run(command, cwd=ROOT, check=True)
    output = ROOT / "installer" / "Output" / f"CodeShield_Setup_{APP_VERSION}.exe"
    if not output.is_file():
        raise RuntimeError(f"安装器未生成预期文件：{output}")
    print(f"安装器：{output}")
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="构建 CodeShield Inno Setup 安装器")
    parser.add_argument("--iscc", help="ISCC.exe 的显式路径")
    arguments = parser.parse_args()
    build_installer(find_compiler(arguments.iscc))
