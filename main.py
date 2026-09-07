from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from codeshield.bootstrap import build_runtime
from codeshield.errors import user_error
from codeshield.resources import demo_project_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CodeShield 本地代码敏感信息扫描工具")
    parser.add_argument(
        "--check",
        action="store_true",
        help="检查配置和数据库后退出，不启动图形界面",
    )
    parser.add_argument("--scan", type=Path, metavar="DIRECTORY", help="扫描指定目录并输出脱敏结果")
    parser.add_argument("--scan-demo", action="store_true", help="扫描项目自带的虚构演示样本")
    parser.add_argument("--explain", action="store_true", help="输出每条 Finding 的评分依据")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        runtime = build_runtime()
    except Exception:
        print(user_error("DB-001"), file=sys.stderr)
        return 2

    if args.check:
        counts = runtime.database.dashboard_counts()
        print(f"CodeShield check passed: {counts['scans']} scans, {counts['findings']} findings")
        return 0

    scan_root = demo_project_path() if args.scan_demo else args.scan
    if scan_root:
        return run_cli_scan(runtime, scan_root, explain=args.explain)

    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        logging.getLogger(__name__).exception("GUI-001 PySide6 导入失败")
        print("缺少 PySide6，请先运行：python -m pip install -r requirements.txt", file=sys.stderr)
        return 2

    try:
        from codeshield.ui.icons import app_icon, configure_windows_app_id
        from codeshield.ui.main_window import MainWindow
    except Exception:
        logging.getLogger(__name__).exception("GUI-002 界面模块加载失败")
        print("CodeShield 图形界面加载失败，请检查本地日志。", file=sys.stderr)
        return 2

    configure_windows_app_id()
    app = QApplication(sys.argv)
    app.setApplicationName("CodeShield")
    app.setWindowIcon(app_icon())
    window = MainWindow(runtime)
    previous_hook = sys.excepthook

    def gui_exception_hook(exc_type, exc_value, traceback) -> None:
        logging.getLogger(__name__).critical(
            "GUI未处理异常 type=%s", exc_type.__name__, exc_info=(exc_type, exc_value, traceback)
        )
        QMessageBox.critical(
            window,
            "CodeShield 发生错误",
            f"{user_error('SCAN-003')}\n技术详情已写入本地日志目录。",
        )

    from PySide6.QtWidgets import QMessageBox
    sys.excepthook = gui_exception_hook
    window.show()
    try:
        return app.exec()
    finally:
        sys.excepthook = previous_hook


def run_cli_scan(runtime, scan_root: Path, explain: bool = False) -> int:
    from codeshield.scanner import ProjectScanner

    try:
        scanner = runtime.create_scanner() if hasattr(runtime, "create_scanner") else ProjectScanner(runtime)
        result = scanner.scan(scan_root)
    except ValueError as exc:
        print(f"扫描失败：{exc}", file=sys.stderr)
        return 2

    stats = result.stats
    print(f"扫描目录：{result.root}")
    print(
        f"候选文件 {stats.candidate_files}，实际扫描 {stats.scanned_files}，"
        f"跳过 {stats.skipped_files}，读取失败 {stats.read_errors}，发现 {len(result.findings)} 项"
    )
    for finding in result.findings:
        print(
            f"{finding.severity.upper():8} {finding.risk_type:20} {finding.score:3} "
            f"{finding.relative_path}:{finding.line_number}:{finding.column} {finding.masked_value}"
        )
        if explain:
            for factor in finding.risk_factors:
                print(f"    {factor.points:+3}  {factor.detail}")
    if result.errors:
        print(f"文件级异常：{len(result.errors)} 项（输出不包含文件内容）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
