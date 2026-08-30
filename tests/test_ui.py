import os
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication
except ImportError:
    QApplication = None

from codeshield.bootstrap import Runtime
from codeshield.config import ConfigStore
from codeshield.database import Database
from codeshield.models import ScanResult, ScanStats
from codeshield.scanner import ProjectScanner
from codeshield.ui.history_page import HistoryPage
from codeshield.ui.comparison_page import ComparisonPage
from codeshield.ui.reports_page import ReportsPage
from codeshield.ui.results_page import ResultsPage
from codeshield.ui.rules_page import RulesPage
from codeshield.ui.scan_page import ScanPage
from codeshield.ui.whitelist_page import WhitelistPage


@unittest.skipIf(QApplication is None, "PySide6 is not installed")
class MainWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def test_all_navigation_pages_can_be_built(self) -> None:
        from codeshield.ui.main_window import MainWindow

        with tempfile.TemporaryDirectory() as directory:
            store = ConfigStore(Path(directory))
            config = store.load()
            database = Database(Path(directory) / "test.db")
            database.initialize()

            window = MainWindow(Runtime(config, store, database))

            self.assertEqual(window.navigation.count(), 8)
            self.assertEqual(window.stack.count(), 9)
            self.assertNotIn("关于", [window.navigation.item(row).text() for row in range(8)])
            self.assertIsInstance(window.scan_page, ScanPage)
            self.assertIsInstance(window.results_page, ResultsPage)
            self.assertIsInstance(window.history_page, HistoryPage)
            self.assertIsInstance(window.rules_page, RulesPage)
            self.assertIsInstance(window.whitelist_page, WhitelistPage)
            self.assertIsInstance(window.comparison_page, ComparisonPage)
            self.assertIsInstance(window.reports_page, ReportsPage)
            self.assertEqual(window.rules_page.table.rowCount(), 11)
            self.assertFalse(window.windowIcon().isNull())
            window.close()

    def test_completed_scan_is_saved_and_history_reuses_results_page(self) -> None:
        from codeshield.ui.main_window import MainWindow

        root = Path(__file__).resolve().parent.parent / "demo_project"
        with tempfile.TemporaryDirectory() as directory:
            store = ConfigStore(Path(directory) / "settings")
            database = Database(Path(directory) / "test.db")
            database.initialize()
            runtime = Runtime(store.load(), store, database)
            result = runtime.create_scanner().scan(root)
            window = MainWindow(runtime)

            window._handle_scan_completed(result)
            self.assertEqual(window.history_page.table.rowCount(), 1)
            self.assertTrue(all(item.database_id for item in result.findings))
            first_id = id(window.results_page)
            scan_id = database.list_scan_history()[0].scan_id
            window._open_history(scan_id)
            self.assertEqual(id(window.results_page), first_id)
            self.assertEqual(window.results_page.table.rowCount(), len(result.findings))
            window.close()

    def test_phase5_pages_refresh_from_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "test.db")
            database.initialize()
            database.add_whitelist("file", "config/demo.py", "本机测试")
            database.save_custom_rule(
                "界面规则",
                "Secret",
                r"marker=(?P<value>\w+)",
                "medium",
                40,
                ["python"],
                "演示规则",
                "移出源码",
            )

            history = HistoryPage(database)
            whitelist = WhitelistPage(database)
            rules = RulesPage(database)
            self.assertEqual(history.table.rowCount(), 0)
            self.assertEqual(whitelist.table.rowCount(), 1)
            self.assertEqual(rules.table.rowCount(), 12)
            self.assertIn("config/demo.py", whitelist.table.item(0, 1).text())
            self.assertFalse(whitelist.delete_button.isEnabled())
            whitelist.table.selectRow(0)
            self.assertTrue(whitelist.delete_button.isEnabled())
            rules.table.selectRow(0)
            self.assertTrue(rules.toggle_button.isEnabled())
            self.assertFalse(rules.edit_button.isEnabled())
            self.assertFalse(rules.delete_button.isEnabled())
            rules.table.selectRow(rules.table.rowCount() - 1)
            self.assertTrue(rules.edit_button.isEnabled())
            self.assertTrue(rules.delete_button.isEnabled())
            history.close()
            whitelist.close()
            rules.close()

    def test_phase6_pages_handle_no_baseline_and_real_history(self) -> None:
        from codeshield.comparison import compare_scans

        root = Path(__file__).resolve().parent.parent / "demo_project"
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "test.db")
            database.initialize()
            first = ProjectScanner(ConfigStore(Path(directory) / "one").load()).scan(root)
            first_id = database.save_scan_result(first)
            second = ProjectScanner(ConfigStore(Path(directory) / "two").load()).scan(root)
            second_id = database.save_scan_result(second)
            records = {item.scan_id: item for item in database.list_scan_history()}

            comparison_page = ComparisonPage()
            comparison_page.set_no_baseline("demo_project")
            self.assertEqual(comparison_page.table.rowCount(), 0)
            comparison_page.set_comparison(
                records[second_id],
                records[first_id],
                compare_scans(first_id, first.findings, second_id, second.findings),
            )
            self.assertEqual(comparison_page.table.rowCount(), 28)

            reports_page = ReportsPage(database)
            self.assertEqual(reports_page.scan_combo.count(), 2)
            self.assertEqual(reports_page.report_type.count(), 2)
            self.assertFalse(reports_page.export_button.isEnabled())
            reports_page.output_dir.setText(directory)
            self.assertTrue(reports_page.export_button.isEnabled())
            comparison_page.close()
            reports_page.close()

    def test_reports_page_empty_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "test.db")
            database.initialize()
            page = ReportsPage(database)
            self.assertFalse(page.export_button.isEnabled())
            self.assertIn("暂无可导出", page.notice.text())
            page.close()

    def test_scan_and_results_pages_build_offscreen(self) -> None:
        from datetime import datetime

        with tempfile.TemporaryDirectory() as directory:
            scan_page = ScanPage(ConfigStore(Path(directory)).load())
            results_page = ResultsPage()
            stats = ScanStats(scan_root="demo", started_at=datetime.now(), status="completed")
            result = ScanResult(Path("demo"), [], stats)

            self.assertFalse(scan_page.start_button.isEnabled())
            scan_page.start_scan()
            self.assertEqual(scan_page.state, "idle")
            self.assertIn("请先选择", scan_page.notice.text())
            results_page.set_result(result)
            self.assertEqual(results_page.table.rowCount(), 0)
            self.assertIn("未发现", results_page.summary_label.text())
            scan_page.close()
            results_page.close()

    def test_results_page_renders_real_findings(self) -> None:
        root = Path(__file__).resolve().parent.parent / "demo_project"
        with tempfile.TemporaryDirectory() as directory:
            result = ProjectScanner(ConfigStore(Path(directory)).load()).scan(root)
            page = ResultsPage()
            page.set_result(result)

            self.assertEqual(page.table.rowCount(), len(result.findings))
            self.assertIn("/ 100", page.detail_title.text())
            self.assertNotEqual(page.masked_value.text(), "—")
            self.assertGreater(page.factors.rowCount(), 0)
            private_row = next(
                index for index, finding in enumerate(page.filtered_findings)
                if finding.risk_type == "Private Key"
            )
            page.table.selectRow(private_row)
            self.assertIn("[MASKED]", page.context.toPlainText())
            self.assertNotIn("intentionally omitted", page.context.toPlainText())
            page.close()

    def test_scan_page_completes_and_can_restart_after_cancel(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "project"
            root.mkdir()
            for index in range(40):
                root.joinpath(f"file_{index}.py").write_text(
                    'password = "DemoPassword"', encoding="utf-8"
                )
            page = ScanPage(ConfigStore(base / "settings").load())
            page.set_project_path(root)
            results = []
            page.scan_completed.connect(results.append)

            page.start_scan()
            page.cancel_scan()
            self._wait_for_page(page)
            self.assertEqual(page.state, "cancelled")
            self.assertTrue(page.start_button.isEnabled())

            page.start_scan()
            self._wait_for_page(page)
            self.assertEqual(page.state, "completed")
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].stats.scanned_files, 40)
            self.assertTrue(page.view_button.isEnabled())
            page.close()

    def test_scan_page_shutdown_waits_for_worker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "project"
            root.mkdir()
            for index in range(40):
                root.joinpath(f"file_{index}.py").write_text("value = 1", encoding="utf-8")
            page = ScanPage(ConfigStore(base / "settings").load())
            page.set_project_path(root)
            page.start_scan()

            self.assertTrue(page.shutdown(3000))
            QApplication.processEvents()
            self.assertTrue(page.thread is None or not page.thread.isRunning())
            page.close()

    @staticmethod
    def _wait_for_page(page: ScanPage) -> None:
        deadline = time.monotonic() + 5
        while page.thread is not None and time.monotonic() < deadline:
            QApplication.processEvents()
            time.sleep(0.005)
        if page.thread is not None:
            page.shutdown()
            raise AssertionError("scan thread did not finish")


if __name__ == "__main__":
    unittest.main()
