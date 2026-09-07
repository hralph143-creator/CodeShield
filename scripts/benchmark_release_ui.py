from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from codeshield.config import AppConfig
from codeshield.models import Finding, RiskFactor, ScanResult, ScanStats
from codeshield.ui.results_page import ResultsPage
from codeshield.ui.scan_page import ScanPage


def build_findings(count: int) -> list[Finding]:
    return [
        Finding(
            rule_id="release.synthetic",
            risk_type="Token",
            severity=("critical", "high", "medium", "low")[index % 4],
            score=80 - index % 40,
            file_path=f"C:/release/src/module_{index:05d}.py",
            relative_path=f"src/module_{index:05d}.py",
            line_number=index + 1,
            column=9,
            language="python",
            masked_value=f"tok***{index % 100:02d}",
            reason="发布界面容量测试",
            suggestion="使用环境变量保存凭证",
            rule_name="发布测试规则",
            risk_factors=(RiskFactor("rule", 40, "规则命中"),),
            context="token = '[MASKED]'",
            fingerprint=f"release-{index:05d}",
            database_id=index + 1,
        )
        for index in range(count)
    ]


def benchmark_results(app: QApplication, count: int) -> dict[str, object]:
    findings = build_findings(count)
    now = datetime.now()
    stats = ScanStats("release-ui", now, now, 1.0, count, count, status="completed")
    page = ResultsPage()
    page.resize(1280, 800)

    started = time.perf_counter()
    page.set_result(ScanResult(Path("release-ui"), findings, stats))
    app.processEvents()
    render_seconds = time.perf_counter() - started

    started = time.perf_counter()
    page.table.scrollToBottom()
    app.processEvents()
    scroll_seconds = time.perf_counter() - started
    scroll_reached_bottom = (
        page.table.verticalScrollBar().value() == page.table.verticalScrollBar().maximum()
    )

    started = time.perf_counter()
    page.search_edit.setText("module_04999")
    app.processEvents()
    filter_seconds = time.perf_counter() - started
    filtered_rows = page.table.rowCount()

    started = time.perf_counter()
    page.search_edit.clear()
    page.table.selectRow(count - 1)
    app.processEvents()
    select_seconds = time.perf_counter() - started
    selected_path = page.current_finding.relative_path if page.current_finding else ""
    page.close()
    return {
        "findings": count,
        "render_seconds": round(render_seconds, 3),
        "scroll_seconds": round(scroll_seconds, 3),
        "scroll_reached_bottom": scroll_reached_bottom,
        "filter_seconds": round(filter_seconds, 3),
        "select_seconds": round(select_seconds, 3),
        "filtered_rows": filtered_rows,
        "selected_path": selected_path,
    }


def benchmark_cancel(app: QApplication, file_count: int) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="CodeShield cancel ") as directory:
        root = Path(directory) / "project"
        root.mkdir()
        for index in range(file_count):
            (root / f"module_{index:05d}.py").write_text("value = 1\n", encoding="utf-8")

        page = ScanPage(AppConfig())
        page.set_project_path(root)
        heartbeats = 0

        def heartbeat() -> None:
            nonlocal heartbeats
            heartbeats += 1

        timer = QTimer()
        timer.timeout.connect(heartbeat)
        timer.start(5)
        page.start_scan()
        QTimer.singleShot(25, page.cancel_scan)
        deadline = time.monotonic() + 15
        while page.thread is not None and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.002)
        cancelled_state = page.state
        restart_enabled = page.start_button.isEnabled()

        page.start_scan()
        while page.thread is not None and time.monotonic() < deadline + 15:
            app.processEvents()
            time.sleep(0.002)
        completed_state = page.state
        timer.stop()
        page.shutdown()
        page.close()
        return {
            "files": file_count,
            "cancelled_state": cancelled_state,
            "restart_enabled": restart_enabled,
            "completed_state_after_restart": completed_state,
            "ui_heartbeats": heartbeats,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings", type=int, default=5000)
    parser.add_argument("--cancel-files", type=int, default=10000)
    args = parser.parse_args()
    app = QApplication.instance() or QApplication([])
    payload = {
        "results_ui": benchmark_results(app, args.findings),
        "scan_cancel": benchmark_cancel(app, args.cancel_files),
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
