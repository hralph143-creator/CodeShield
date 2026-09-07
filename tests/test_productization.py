import logging
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from codeshield.config import AppConfig, ConfigStore
from codeshield.database import Database, MAX_DATABASE_BACKUPS
from codeshield.logging_setup import LOG_BACKUP_COUNT, MAX_LOG_BYTES, configure_logging
from codeshield.reporting import build_html_report
from codeshield.rules import validate_rule_pattern
from codeshield.scanner import ProjectScanner


class ProductizationTests(unittest.TestCase):
    def test_scan_mode_config_round_trip_and_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ConfigStore(Path(directory))
            store.save(AppConfig(scan_mode="full"))
            self.assertEqual(store.load().scan_mode, "full")
        self.assertEqual(AppConfig.from_dict({"scan_mode": "unknown"}).scan_mode, "standard")

    def test_standard_full_and_custom_scan_modes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            samples = {
                "src/app.py": 'api_key = "A9fK2mQ7xT4vN8pR3sW6yB1c"',
                "tests/test_app.py": 'token = "A9fK2mQ7xT4vN8pR3sW6yB1c"',
                "node_modules/pkg/index.js": 'token = "A9fK2mQ7xT4vN8pR3sW6yB1c"',
                "build/generated.py": 'secret = "A9fK2mQ7xT4vN8pR3sW6yB1c"',
            }
            for relative, content in samples.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")

            standard = ProjectScanner(AppConfig(scan_mode="standard")).scan(root)
            full = ProjectScanner(AppConfig(scan_mode="full")).scan(root)
            custom = ProjectScanner(
                AppConfig(scan_mode="custom", ignored_dirs=["tests"], included_extensions=[".py"])
            ).scan(root)

        self.assertEqual(standard.stats.scanned_files, 2)
        self.assertEqual(full.stats.scanned_files, 4)
        self.assertEqual(custom.stats.scanned_files, 2)
        self.assertTrue(any(item.relative_path.endswith("test_app.py") for item in standard.findings))
        generated = next(item for item in full.findings if "build" in item.relative_path)
        self.assertTrue(any(factor.key == "generated_source" for factor in generated.risk_factors))

    def test_source_classification_is_user_facing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "src" / "app.py"
            path.parent.mkdir()
            path.write_text('api_key = "A9fK2mQ7xT4vN8pR3sW6yB1c"', encoding="utf-8")
            finding = ProjectScanner(AppConfig()).scan(root).findings[0]
        self.assertTrue(any(f.key == "project_source" and "项目源码" in f.detail for f in finding.risk_factors))

    def test_logging_redaction_pattern_is_detector_feature(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "codeshield" / "logging_setup.py"
            path.parent.mkdir()
            path.write_text('REDACT = "-----BEGIN PRIVATE KEY-----"', encoding="utf-8")
            finding = ProjectScanner(AppConfig()).scan(root).findings[0]
        self.assertEqual(finding.severity, "low")
        self.assertTrue(any(f.key == "detector_rule_feature" for f in finding.risk_factors))

    def test_safe_rotating_log_redacts_credentials(self) -> None:
        raw = "A9fK2mQ7xT4vN8pR3sW6yB1cD5eH0jL"
        with tempfile.TemporaryDirectory() as directory:
            path = configure_logging(Path(directory))
            logging.getLogger("codeshield.test").error("token=%s", raw)
            for handler in logging.getLogger().handlers:
                handler.flush()
            content = path.read_text(encoding="utf-8")
            handlers = [handler for handler in logging.getLogger().handlers if getattr(handler, "baseFilename", "") == str(path.resolve())]
            max_bytes = handlers[0].maxBytes
            backup_count = handlers[0].backupCount
            logging.getLogger().removeHandler(handlers[0])
            handlers[0].close()
        self.assertNotIn(raw, content)
        self.assertIn("[MASKED]", content)
        self.assertEqual(max_bytes, MAX_LOG_BYTES)
        self.assertEqual(backup_count, LOG_BACKUP_COUNT)

    def test_database_migration_creates_backup_only_when_needed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "codeshield.db"
            connection = sqlite3.connect(path)
            connection.execute("CREATE TABLE legacy (id INTEGER PRIMARY KEY)")
            connection.commit()
            connection.close()
            database = Database(path)
            database.initialize()
            backups = list((path.parent / "backups").glob("codeshield_*.db"))
            self.assertEqual(len(backups), 1)
            database.initialize()
            self.assertEqual(len(list((path.parent / "backups").glob("codeshield_*.db"))), 1)

    def test_failed_migration_rolls_back_and_preserves_backup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "codeshield.db"
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("CREATE TABLE scan_history (id INTEGER PRIMARY KEY, sentinel TEXT)")
                connection.execute("INSERT INTO scan_history (sentinel) VALUES ('kept')")
                connection.commit()
            with self.assertRaises(sqlite3.OperationalError):
                Database(path).initialize()
            with closing(sqlite3.connect(path)) as connection:
                row = connection.execute("SELECT sentinel FROM scan_history").fetchone()
                columns = [item[1] for item in connection.execute("PRAGMA table_info(scan_history)")]
            self.assertEqual(row[0], "kept")
            self.assertEqual(columns, ["id", "sentinel"])
            self.assertEqual(len(list((path.parent / "backups").glob("codeshield_*.db"))), 1)

    def test_database_backup_retention(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "codeshield.db"
            path.write_bytes(b"legacy")
            database = Database(path)
            for _ in range(MAX_DATABASE_BACKUPS + 2):
                database._backup_before_migration()
            self.assertEqual(len(list((path.parent / "backups").glob("codeshield_*.db"))), MAX_DATABASE_BACKUPS)

    def test_regex_length_and_nested_repetition_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_rule_pattern("x" * 2001 + "(?P<value>x)")
        with self.assertRaises(ValueError):
            validate_rule_pattern(r"(?P<value>(a+)+)")

    def test_bad_runtime_regex_isolated(self) -> None:
        from unittest.mock import Mock
        from codeshield.models import Rule
        from codeshield.rules import RuleDetector

        broken_pattern = Mock()
        broken_pattern.finditer.side_effect = RuntimeError("broken")
        rule = Rule("broken", "broken", "Token", broken_pattern, "high", 60, frozenset({"python"}), "", "")
        with self.assertLogs("codeshield.rules", level="WARNING"):
            findings = RuleDetector([rule], AppConfig()).detect("token='abcdefghi'", Path("a.py"), Path("a.py"), "python")
        self.assertEqual(findings, [])

    def test_html_escapes_multiple_attack_shapes(self) -> None:
        from dataclasses import replace
        from datetime import datetime
        from codeshield.models import Finding, ScanHistoryRecord, ScanResult, ScanStats

        finding = Finding(
            "x", "Token", "low", 10, "x", '<img src=x onerror=alert(1)>.py', 1, 1,
            "python", "&<>\"'", "<script>alert(1)</script>", "move & delete", rule_name="<script>x</script>",
        )
        now = datetime.now()
        record = ScanHistoryRecord(1, "x", "x", now, now, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, "completed")
        result = ScanResult(Path("x"), [finding], ScanStats("x", now, now, status="completed"))
        html = build_html_report(record, result)
        self.assertNotIn("<img src=x", html)
        self.assertNotIn("<script>alert", html)
        self.assertIn("&lt;img", html)
        self.assertIn("&amp;&lt;&gt;&quot;&#x27;", html)

    def test_thousand_file_scan_and_large_cancel(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index in range(1000):
                (root / f"module_{index}.py").write_text("value = 1", encoding="utf-8")
            result = ProjectScanner(AppConfig()).scan(root)
            self.assertEqual(result.stats.scanned_files, 1000)
            cancelled = ProjectScanner(AppConfig()).scan(
                root, is_cancelled=lambda: False if result.stats.scanned_files < 0 else True
            )
            self.assertEqual(cancelled.stats.status, "cancelled")


if __name__ == "__main__":
    unittest.main()
