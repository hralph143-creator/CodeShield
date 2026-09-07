from pathlib import Path

from codeshield.version import APP_NAME


ROOT = Path(SPECPATH)
ICON = ROOT / "resources" / "app_icon.ico"
VERSION_INFO = ROOT / "build" / "version_info.txt"

a = Analysis(
    [str(ROOT / "main.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[
        (str(ROOT / "1.png"), "."),
        (str(ICON), "resources"),
        (str(ROOT / "rules" / "builtin_rules.json"), "rules"),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "unittest", "tkinter"],
    noarchive=False,
    optimize=1,
)
# PySide6 6.11 uses Windows' system ICU. A build host may expose unrelated ICU
# DLLs through PATH (for example Poppler); bundling them shadows System32 and
# causes a Qt6Core entry-point failure on startup.
external_icu = {"icuuc.dll", "icudt78.dll"}
a.binaries = [item for item in a.binaries if Path(item[0]).name.casefold() not in external_icu]
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name=APP_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    icon=str(ICON),
    version=str(VERSION_INFO),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name=APP_NAME,
)
