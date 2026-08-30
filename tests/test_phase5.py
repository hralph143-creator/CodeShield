import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from pathlib import Path

from codeshield.config import AppConfig
from codeshield.database import Database
from codeshield.scanner import ProjectScanner


DEMO_ROOT = Path(__file__).resolve().parent.parent / "demo_project"


class Phase5DatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.database = Database(self.base / "codeshield.db")
        self.database.initialize()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def scanner(self) -> ProjectScanner:
        return ProjectScanner(
            AppConfig(),
            additional_rules=self.database.active_custom_rules(),
            disabled_rule_ids=self.database.disabled_builtin_rule_ids(),
            whitelist_matcher=self.database.is_whitelisted,
        )

    def test_scan_snapshot_round_trip_and_restart(self) -> None:
        result = self.scanner().scan(DEMO_ROOT)
        scan_id = self.database.save_scan_result(result)
        reopened = Database(self.database.path)
        reopened.initialize()
        restored = reopened.load_scan_result(scan_id)

        self.assertEqual(len(restored.findings), len(result.findings))
        self.assertEqual(restored.findings[0].risk_factors, result.findings[0].risk_factors)
        self.assertTrue(all(item.database_id for item in restored.findings))
        self.assertEqual(reopened.list_scan_history()[0].scan_id, scan_id)

    def test_snapshot_never_stores_original_secret(self) -> None:
        result = self.scanner().scan(DEMO_ROOT)
        self.database.save_scan_result(result)
        with closing(self.database.connect()) as connection:
            dump = " ".join(
                str(value)
                for row in connection.execute("SELECT * FROM scan_results")
                for value in row
            )
        self.assertNotIn("A9fK2mQ7xT4vN8pR3sW6yB1cD5eH0jL", dump)
        self.assertNotIn("DemoPass-NotValid", dump)
        self.assertIn("[MASKED]", dump)

    def test_snapshot_transaction_rolls_back_on_result_failure(self) -> None:
        result = self.scanner().scan(DEMO_ROOT)
        result.findings[0] = replace(result.findings[0], score=101)
        with self.assertRaises(sqlite3.IntegrityError):
            self.database.save_scan_result(result)
        self.assertEqual(self.database.list_scan_history(), [])

    def test_status_update_survives_reload_without_changing_scan_fact(self) -> None:
        result = self.scanner().scan(DEMO_ROOT)
        scan_id = self.database.save_scan_result(result)
        item = result.findings[0]
        original = (item.score, item.severity, item.risk_factors)
        self.database.update_finding_status(item.database_id, "false_positive")
        restored = self.database.load_scan_result(scan_id).findings[0]
        self.assertEqual(restored.status, "false_positive")
        self.assertEqual((restored.score, restored.severity, restored.risk_factors), original)

    def test_delete_history_cascades_results(self) -> None:
        result = self.scanner().scan(DEMO_ROOT)
        scan_id = self.database.save_scan_result(result)
        self.database.delete_scan(scan_id)
        with closing(self.database.connect()) as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM scan_results WHERE scan_id = ?", (scan_id,)
            ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_fingerprint_whitelist_toggle_delete_and_rescan(self) -> None:
        first = self.scanner().scan(DEMO_ROOT)
        fingerprint = first.findings[0].fingerprint
        entry_id = self.database.add_whitelist("fingerprint", fingerprint, "演示误报")
        second = self.scanner().scan(DEMO_ROOT)
        self.assertNotIn(fingerprint, {item.fingerprint for item in second.findings})
        self.assertEqual(second.stats.suppressed_findings, 1)

        self.database.set_whitelist_enabled(entry_id, False)
        self.assertIn(fingerprint, {item.fingerprint for item in self.scanner().scan(DEMO_ROOT).findings})
        self.database.delete_whitelist(entry_id)
        self.assertEqual(self.database.list_whitelist(), [])

    def test_path_directory_and_rule_whitelists(self) -> None:
        first = self.scanner().scan(DEMO_ROOT)
        target = first.findings[0]
        self.database.add_whitelist("file", target.relative_path)
        self.database.add_whitelist("directory", "tests")
        self.database.add_whitelist("rule", "email_address")
        findings = self.scanner().scan(DEMO_ROOT).findings
        self.assertFalse(any(item.relative_path == target.relative_path for item in findings))
        self.assertFalse(any(item.relative_path.replace("\\", "/").startswith("tests/") for item in findings))
        self.assertFalse(any(item.rule_id == "email_address" for item in findings))

    def test_custom_rule_crud_and_real_scan(self) -> None:
        pattern = r"demo_marker\s*=\s*[\"'](?P<value>[^\"']+)[\"']"
        rule_id = self.database.save_custom_rule(
            "演示标记", "Secret", pattern, "medium", 40, ["python"], "发现演示标记", "移出源码"
        )
        project = self.base / "project"
        project.mkdir()
        project.joinpath("sample.py").write_text(
            'demo_marker = "CustomRuleValue123"', encoding="utf-8"
        )
        reopened = Database(self.database.path)
        reopened.initialize()
        findings = ProjectScanner(
            AppConfig(), additional_rules=reopened.active_custom_rules()
        ).scan(project).findings
        self.assertTrue(any(item.rule_id == rule_id for item in findings))

        self.database.set_custom_rule_enabled(rule_id, False)
        self.assertFalse(any(item.rule_id == rule_id for item in self.scanner().scan(project).findings))
        self.database.delete_custom_rule(rule_id)
        self.assertFalse(any(item.rule_id == rule_id for item in self.database.list_managed_rules()))

    def test_invalid_custom_regex_and_builtin_protection(self) -> None:
        with self.assertRaises(Exception):
            self.database.save_custom_rule(
                "错误规则", "Secret", "([", "medium", 40, ["python"], "", ""
            )
        builtins = [rule for rule in self.database.list_managed_rules() if rule.builtin]
        self.assertEqual(len(builtins), 11)
        with self.assertRaises(ValueError):
            self.database.delete_custom_rule(builtins[0].rule_id)

    def test_builtin_disable_is_used_by_next_scan(self) -> None:
        project = self.base / "builtin"
        project.mkdir()
        project.joinpath("sample.py").write_text(
            'password = "HardcodedPassword123"', encoding="utf-8"
        )
        self.assertTrue(any(item.rule_id == "password_assignment" for item in self.scanner().scan(project).findings))
        self.database.set_builtin_rule_enabled("password_assignment", False)
        self.assertFalse(any(item.rule_id == "password_assignment" for item in self.scanner().scan(project).findings))


if __name__ == "__main__":
    unittest.main()
