from __future__ import annotations

import argparse
import sys
from pathlib import Path

from codeshield.bootstrap import build_runtime


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
    runtime = build_runtime()

    if args.check:
        counts = runtime.database.dashboard_counts()
        print(f"CodeShield check passed: {counts['scans']} scans, {counts['findings']} findings")
        return 0

    scan_root = Path(__file__).resolve().parent / "demo_project" if args.scan_demo else args.scan
    if scan_root:
        return run_cli_scan(runtime, scan_root, explain=args.explain)

    try:
        from PySide6.QtWidgets import QApplication
        from codeshield.ui.icons import app_icon, configure_windows_app_id
        from codeshield.ui.main_window import MainWindow
    except ImportError:
        print("缺少 PySide6，请先运行：python -m pip install -r requirements.txt", file=sys.stderr)
        return 2

    configure_windows_app_id()
    app = QApplication(sys.argv)
    app.setApplicationName("CodeShield")
    app.setWindowIcon(app_icon())
    window = MainWindow(runtime)
    window.show()
    return app.exec()


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
