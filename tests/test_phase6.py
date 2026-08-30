import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from codeshield.comparison import compare_scans
from codeshield.config import AppConfig
from codeshield.database import Database
from codeshield.models import ScanResult
from codeshield.reporting import (
    build_html_report,
    build_json_report,
    default_report_name,
    export_report,
    safe_filename,
)
from codeshield.scanner import ProjectScanner


DEMO_ROOT = Path(__file__).resolve().parent.parent / "demo_project"


class Phase6Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.database = Database(self.base / "codeshield.db")
        self.database.initialize()
        self.scanner = ProjectScanner(AppConfig())

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_comparison_identifies_all_three_changes(self) -> None:
        baseline = self.scanner.scan(DEMO_ROOT)
        persistent = baseline.findings[0]
        resolved = baseline.findings[1]
        added = replace(baseline.findings[2], fingerprint="new-fingerprint")
        comparison = compare_scans(1, [persistent, resolved], 2, [persistent, added])
        self.assertEqual((comparison.new_count, comparison.persistent_count, comparison.resolved_count), (1, 1, 1))

    def test_comparison_handles_identical_empty_and_duplicate_fingerprints(self) -> None:
        result = self.scanner.scan(DEMO_ROOT)
        finding = result.findings[0]
        identical = compare_scans(1, [finding, finding], 2, [finding, finding])
        empty = compare_scans(1, [], 2, [])
        self.assertEqual((identical.new_count, identical.persistent_count, identical.resolved_count), (0, 1, 0))
        self.assertEqual((empty.new_count, empty.persistent_count, empty.resolved_count), (0, 0, 0))

    def test_previous_completed_scan_skips_cancelled(self) -> None:
        first = self.scanner.scan(DEMO_ROOT)
        first_id = self.database.save_scan_result(first)
        cancelled = self.scanner.scan(DEMO_ROOT)
        cancelled.stats.status = "cancelled"
        self.database.save_scan_result(cancelled)
        current = self.scanner.scan(DEMO_ROOT)
        current_id = self.database.save_scan_result(current)
        previous = self.database.previous_completed_scan(current_id)
        self.assertIsNotNone(previous)
        self.assertEqual(previous.scan_id, first_id)
        self.assertIsNone(self.database.previous_completed_scan(first_id))

    def test_real_sqlite_comparison_and_whitelist_difference(self) -> None:
        first = self.scanner.scan(DEMO_ROOT)
        first_id = self.database.save_scan_result(first)
        self.database.add_whitelist("fingerprint", first.findings[0].fingerprint)
        second = ProjectScanner(AppConfig(), whitelist_matcher=self.database.is_whitelisted).scan(DEMO_ROOT)
        second_id = self.database.save_scan_result(second)
        previous = self.database.previous_completed_scan(second_id)
        comparison = compare_scans(
            previous.scan_id,
            self.database.load_scan_result(previous.scan_id).findings,
            second_id,
            self.database.load_scan_result(second_id).findings,
        )
        self.assertEqual(comparison.resolved_count, 1)
        self.assertEqual(second.stats.suppressed_findings, 1)
        self.assertEqual(self.database.list_scan_history()[0].suppressed_findings, 1)
        self.assertEqual(previous.scan_id, first_id)

    def test_json_report_has_stable_safe_structure(self) -> None:
        record, result = self._saved_result()
        content = build_json_report(record, result)
        payload = json.loads(content)
        self.assertEqual(set(payload), {"tool", "scan", "summary", "findings"})
        self.assertEqual(payload["tool"]["report_version"], 1)
        self.assertIn("risk_factors", payload["findings"][0])
        self.assertIsNone(payload["summary"]["comparison"])
        self.assertNotIn("A9fK2mQ7xT4vN8pR3sW6yB1cD5eH0jL", content)
        self.assertNotIn("raw_value", content)
        self.assertNotIn("original_value", content)

    def test_html_report_is_escaped_offline_and_printable(self) -> None:
        record, result = self._saved_result()
        item = replace(
            result.findings[0],
            rule_name="<script>alert(1)</script>",
            relative_path="src/a&b.py",
            suggestion="move </style> outside",
        )
        changed = ScanResult(result.root, [item], result.stats, scan_id=result.scan_id)
        content = build_html_report(record, changed)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", content)
        self.assertIn("src/a&amp;b.py", content)
        self.assertIn("move &lt;/style&gt; outside", content)
        self.assertNotIn("<script", content.casefold())
        self.assertNotIn("http://", content)
        self.assertNotIn("https://", content)
        self.assertIn("@media print", content)

    def test_html_private_key_and_risk_factors_remain_masked(self) -> None:
        record, result = self._saved_result()
        content = build_html_report(record, result)
        self.assertIn("-----BEGIN PRIVATE KEY----- [MASKED]", content)
        self.assertIn("检测依据", content)
        self.assertIn("修复建议", content)
        self.assertNotIn("A9fK2mQ7xT4vN8pR3sW6yB1cD5eH0jL", content)

    def test_zero_and_large_reports_generate(self) -> None:
        record, result = self._saved_result()
        empty = ScanResult(result.root, [], result.stats, scan_id=result.scan_id)
        self.assertIn("本次扫描没有风险项", build_html_report(record, empty))
        large = ScanResult(result.root, result.findings * 100, result.stats, scan_id=result.scan_id)
        self.assertGreater(len(build_html_report(record, large)), 100_000)

    def test_filename_is_windows_safe_and_export_never_overwrites(self) -> None:
        record, result = self._saved_result()
        unsafe = replace(record, project_name='CON<>:"/\\|?* 项目')
        name = default_report_name(unsafe, "html")
        self.assertFalse(any(character in name for character in '<>:"/\\|?*'))
        self.assertEqual(safe_filename("CON"), "_CON")
        first = export_report(self.base, "html", unsafe, result)
        second = export_report(self.base, "html", unsafe, result)
        json_path = export_report(self.base, "json", unsafe, result)
        self.assertTrue(first.exists() and second.exists() and json_path.exists())
        self.assertNotEqual(first, second)
        self.assertEqual(json.loads(json_path.read_text(encoding="utf-8"))["tool"]["name"], "CodeShield")

    def test_dashboard_distribution_and_recent_scans_are_real(self) -> None:
        record, _result = self._saved_result()
        counts = self.database.dashboard_severity_counts()
        self.assertEqual(sum(counts.values()), record.finding_count)
        self.assertEqual(self.database.recent_completed_scans(1)[0].scan_id, record.scan_id)

    def _saved_result(self):
        result = self.scanner.scan(DEMO_ROOT)
        scan_id = self.database.save_scan_result(result)
        record = next(item for item in self.database.list_scan_history() if item.scan_id == scan_id)
        return record, self.database.load_scan_result(scan_id)


if __name__ == "__main__":
    unittest.main()
