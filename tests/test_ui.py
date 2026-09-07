import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication, QMessageBox
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
from codeshield.ui.settings_page import SettingsPage
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

            self.assertEqual(window.navigation.count(), 7)
            self.assertEqual(window.stack.count(), 8)
            navigation_titles = [window.navigation.item(row).text() for row in range(7)]
            self.assertNotIn("关于", navigation_titles)
            self.assertNotIn("白名单", navigation_titles)
            self.assertIsInstance(window.scan_page, ScanPage)
            self.assertIsInstance(window.results_page, ResultsPage)
            self.assertIsInstance(window.history_page, HistoryPage)
            self.assertIsInstance(window.rules_page, RulesPage)
            self.assertIsInstance(window.whitelist_page, WhitelistPage)
            self.assertEqual(window.rule_management_tabs.count(), 2)
            self.assertEqual(window.rule_management_tabs.tabText(0), "规则管理")
            self.assertEqual(window.rule_management_tabs.tabText(1), "白名单")
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
            self.assertEqual(
                window.operational_values["candidates"].text(),
                str(result.stats.candidate_files),
            )
            self.assertEqual(window.language_table.rowCount(), len(result.stats.language_files))
            window._load_latest_scan_path()
            self.assertEqual(window.navigation.currentRow(), 1)
            self.assertEqual(Path(window.scan_page.path_edit.text()), root)
            window._open_latest_result()
            self.assertEqual(window.navigation.currentRow(), 2)
            first_id = id(window.results_page)
            scan_id = database.list_scan_history()[0].scan_id
            window._open_history(scan_id)
            self.assertEqual(id(window.results_page), first_id)
            self.assertEqual(window.results_page.table.rowCount(), len(result.findings))
            window.close()

    def test_stack_pages_remain_isolated_during_repeated_navigation(self) -> None:
        from PySide6.QtCore import Qt
        from codeshield.ui.main_window import MainWindow

        with tempfile.TemporaryDirectory() as directory:
            store = ConfigStore(Path(directory))
            database = Database(Path(directory) / "test.db")
            database.initialize()
            window = MainWindow(Runtime(store.load(), store, database))
            window.show()
            self.app.processEvents()

            surfaces = [*window.pages.values(), window.comparison_page]
            self.assertTrue(all(page.objectName() == "pageSurface" for page in surfaces))
            self.assertTrue(
                all(page.testAttribute(Qt.WidgetAttribute.WA_StyledBackground) for page in surfaces)
            )
            for row in (1, 4, 0, 3, 2, 0):
                window.navigation.setCurrentRow(row)
                self.app.processEvents()
                current = window.stack.currentWidget()
                self.assertIs(current, window.pages[window._nav_kinds[row]])
                self.assertEqual(
                    [page for page in surfaces if page.isVisibleTo(window.stack)],
                    [current],
                )

            window._set_stack_page(window.comparison_page)
            self.app.processEvents()
            self.assertIs(window.stack.currentWidget(), window.comparison_page)
            self.assertEqual(
                [page for page in surfaces if page.isVisibleTo(window.stack)],
                [window.comparison_page],
            )
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
            self.assertTrue(whitelist.delete_button.isEnabled())
            whitelist.table.selectRow(0)
            self.assertTrue(whitelist.delete_button.isEnabled())
            rules.table.selectRow(0)
            self.assertTrue(rules.toggle_button.isEnabled())
            self.assertTrue(rules.edit_button.isEnabled())
            self.assertTrue(rules.delete_button.isEnabled())
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
            self.assertTrue(reports_page.export_button.isEnabled())
            reports_page.output_dir.setText(directory)
            self.assertTrue(reports_page.export_button.isEnabled())
            comparison_page.close()
            reports_page.close()

    def test_reports_page_empty_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "test.db")
            database.initialize()
            page = ReportsPage(database)
            self.assertTrue(page.export_button.isEnabled())
            self.assertIn("暂无可导出", page.notice.text())
            page.close()

    def test_scan_and_results_pages_build_offscreen(self) -> None:
        from datetime import datetime

        with tempfile.TemporaryDirectory() as directory:
            scan_page = ScanPage(ConfigStore(Path(directory)).load())
            results_page = ResultsPage()
            stats = ScanStats(scan_root="demo", started_at=datetime.now(), status="completed")
            result = ScanResult(Path("demo"), [], stats)

            self.assertTrue(scan_page.start_button.isEnabled())
            with patch.object(QMessageBox, "information") as information:
                scan_page.start_button.click()
                information.assert_called_once()
            self.assertEqual(scan_page.state, "idle")
            self.assertIn("请先选择", scan_page.notice.text())
            self.assertTrue(scan_page.cancel_button.isEnabled())
            self.assertIn("开始扫描后", scan_page.cancel_button.toolTip())
            self.assertTrue(scan_page.view_button.isEnabled())
            self.assertIn("完成一次扫描后", scan_page.view_button.toolTip())
            from codeshield.ui.styles import APP_STYLE
            self.assertIn("#primaryButton:disabled", APP_STYLE)
            self.assertIn("#dangerButton:disabled", APP_STYLE)
            results_page.set_result(result)
            self.assertEqual(results_page.table.rowCount(), 0)
            self.assertIn("未发现", results_page.summary_label.text())
            from PySide6.QtCore import QUrl
            self.assertEqual(
                scan_page._directory_from_urls([QUrl.fromLocalFile(directory)]),
                Path(directory),
            )
            scan_page.close()
            results_page.close()

    def test_action_buttons_show_precondition_dialogs_instead_of_being_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = Database(root / "test.db")
            database.initialize()
            scan_page = ScanPage(ConfigStore(root / "settings").load())
            history = HistoryPage(database)
            whitelist = WhitelistPage(database)
            rules = RulesPage(database)
            reports = ReportsPage(database)
            results = ResultsPage()

            with patch.object(QMessageBox, "information") as information:
                scan_page.start_button.click()
                scan_page.cancel_button.click()
                scan_page.view_button.click()
                history.compare_button.click()
                history.delete_button.click()
                whitelist.toggle_button.click()
                whitelist.delete_button.click()
                rules.edit_button.click()
                rules.toggle_button.click()
                rules.delete_button.click()
                reports.export_button.click()
                reports.open_button.click()
                results.whitelist_button.click()
                results.copy_button.click()
                results.open_location_button.click()
                self.assertEqual(information.call_count, 15)

            for button in (
                scan_page.start_button,
                scan_page.cancel_button,
                scan_page.view_button,
                history.compare_button,
                history.delete_button,
                whitelist.toggle_button,
                whitelist.delete_button,
                rules.edit_button,
                rules.toggle_button,
                rules.delete_button,
                reports.choose_button,
                reports.export_button,
                reports.open_button,
                results.whitelist_button,
                results.copy_button,
                results.open_location_button,
            ):
                self.assertTrue(button.isEnabled(), button.text())

            for page in (scan_page, history, whitelist, rules, reports, results):
                page.close()

    def test_settings_restore_changes_config_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = ConfigStore(root / "settings")
            config = store.load()
            database = Database(root / "test.db")
            database.initialize()
            result = ProjectScanner(config).scan(root / "settings")
            database.save_scan_result(result)
            page = SettingsPage(config, store)
            page.mode_combo.setCurrentIndex(page.mode_combo.findData("full"))
            page.save()
            self.assertEqual(store.load().scan_mode, "full")
            page.reset_button.click()
            page.save_button.click()
            self.assertEqual(store.load().scan_mode, "standard")
            self.assertEqual(len(database.list_scan_history()), 1)
            page.close()

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
            with patch.object(QMessageBox, "information") as information:
                page.copy_button.click()
                information.assert_called_once()
            self.assertIn("脱敏内容：", QApplication.clipboard().text())
            self.assertIn(page.current_finding.masked_value, QApplication.clipboard().text())
            with patch("codeshield.ui.results_page.QDesktopServices.openUrl", return_value=True) as open_url:
                page.open_location_button.click()
                open_url.assert_called_once()
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
