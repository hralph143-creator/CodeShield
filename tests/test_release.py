import json
import os
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import codeshield
from codeshield.config import ConfigStore
from codeshield.database import Database
from codeshield.reporting import export_report
from codeshield.resources import application_root, demo_project_path, resource_path
from codeshield.rules import load_rules
from codeshield.scanner import ProjectScanner
from codeshield.version import APP_NAME, APP_VERSION


ROOT = Path(__file__).resolve().parent.parent


class ReleaseEngineeringTests(unittest.TestCase):
    def test_single_version_source_is_consistent(self) -> None:
        self.assertEqual(APP_NAME, "CodeShield")
        self.assertEqual(APP_VERSION, "1.0.0")
        self.assertEqual(codeshield.__version__, APP_VERSION)
        self.assertIn("from codeshield.version import APP_NAME", (ROOT / "CodeShield.spec").read_text(encoding="utf-8"))
        self.assertNotIn("AppVersion=1.0.0", (ROOT / "installer/CodeShield.iss").read_text(encoding="utf-8"))

    def test_source_resource_paths_exist(self) -> None:
        self.assertEqual(application_root(), ROOT)
        for relative in ("1.png", "resources/app_icon.ico", "rules/builtin_rules.json"):
            self.assertTrue(resource_path(*relative.split("/")).is_file(), relative)

    def test_frozen_resource_root_simulation(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.object(sys, "_MEIPASS", directory, create=True):
            self.assertEqual(application_root(), Path(directory))
            self.assertEqual(resource_path("rules", "builtin_rules.json"), Path(directory) / "rules/builtin_rules.json")

    def test_demo_project_path_in_source_mode(self) -> None:
        self.assertEqual(demo_project_path(), ROOT / "demo_project")

    def test_clean_user_data_initialization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ConfigStore(Path(directory) / "CodeShield")
            config = store.load()
            database = Database(store.data_dir / "codeshield.db")
            database.initialize()
            self.assertEqual(config.scan_mode, "standard")
            self.assertTrue(store.path.is_file())
            self.assertEqual(database.list_scan_history(), [])
            self.assertEqual(database.list_whitelist(), [])
            self.assertEqual(len([rule for rule in database.list_managed_rules() if not rule.builtin]), 0)
            self.assertEqual(len(load_rules().rules), 11)

    def test_read_only_install_location_does_not_receive_user_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            install = base / "Program Files" / "CodeShield"
            local = base / "LocalAppData"
            install.mkdir(parents=True)
            with patch.dict(os.environ, {"LOCALAPPDATA": str(local)}):
                store = ConfigStore()
                store.load()
                Database(store.data_dir / "codeshield.db").initialize()
            self.assertEqual(list(install.iterdir()), [])
            self.assertTrue((local / "CodeShield/settings.json").is_file())
            self.assertTrue((local / "CodeShield/codeshield.db").is_file())

    def test_build_configuration_contains_only_required_resources(self) -> None:
        spec = (ROOT / "CodeShield.spec").read_text(encoding="utf-8")
        self.assertIn('"builtin_rules.json"', spec)
        self.assertIn('"app_icon.ico"', spec)
        self.assertIn("console=False", spec)
        self.assertIn('external_icu = {"icuuc.dll", "icudt78.dll"}', spec)
        for forbidden in ("tests", ".venv", ".pytest_cache", "*.db", "*.log"):
            self.assertNotIn(forbidden, spec)

    def test_installer_script_has_required_install_and_uninstall_contract(self) -> None:
        script = (ROOT / "installer/CodeShield.iss").read_text(encoding="utf-8")
        self.assertIn("DefaultDirName={autopf}\\CodeShield", script)
        self.assertIn("CodeShield_Setup_{#AppVersion}", script)
        self.assertIn("{group}\\CodeShield", script)
        self.assertIn("{uninstallexe}", script)
        self.assertNotIn("LOCALAPPDATA", script.upper())

    def test_chinese_and_special_project_path_scan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "测试项目" / "示例 工程(1)"
            project.mkdir(parents=True)
            project.joinpath("配置.py").write_text('api_key = "A9fK2mQ7xT4vN8pR3sW6yB1c"', encoding="utf-8")
            result = ProjectScanner(ConfigStore(Path(directory) / "settings").load()).scan(project)
        self.assertEqual(result.stats.scanned_files, 1)
        self.assertEqual(len(result.findings), 1)
        self.assertIn("配置.py", result.findings[0].relative_path)

    def test_special_path_html_and_json_report_output(self) -> None:
        demo = ROOT / "demo_project"
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            output = base / "报告 输出(1)"
            output.mkdir()
            database = Database(base / "codeshield.db")
            database.initialize()
            result = ProjectScanner(ConfigStore(base / "settings").load()).scan(demo)
            scan_id = database.save_scan_result(result)
            record = next(item for item in database.list_scan_history() if item.scan_id == scan_id)
            html_path = export_report(output, "html", record, database.load_scan_result(scan_id))
            json_path = export_report(output, "json", record, database.load_scan_result(scan_id))
            self.assertTrue(html_path.is_file())
            self.assertTrue(json_path.is_file())
            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8"))["tool"]["version"], APP_VERSION)

    def test_legacy_data_survives_upgrade(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "codeshield.db"
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("CREATE TABLE custom_marker (value TEXT)")
                connection.execute("INSERT INTO custom_marker VALUES ('preserved')")
                connection.commit()
            Database(path).initialize()
            with closing(sqlite3.connect(path)) as connection:
                value = connection.execute("SELECT value FROM custom_marker").fetchone()[0]
                version = connection.execute("PRAGMA user_version").fetchone()[0]
            self.assertEqual(value, "preserved")
            self.assertEqual(version, 4)
            self.assertEqual(len(list((path.parent / "backups").glob("codeshield_*.db"))), 1)


if __name__ == "__main__":
    unittest.main()
