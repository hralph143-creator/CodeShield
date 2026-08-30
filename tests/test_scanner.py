import os
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from codeshield.config import AppConfig
from codeshield.scanner import ProjectScanner, is_probably_binary, read_source_file
from main import run_cli_scan


class ScannerTests(unittest.TestCase):
    def test_recursive_scan_filters_and_ignores(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "node_modules").mkdir()
            (root / "src" / "app.py").write_text('password = "DemoPassword"', encoding="utf-8")
            (root / "src" / "notes.txt").write_text('password = "IgnoredValue"', encoding="utf-8")
            (root / "node_modules" / "dep.js").write_text('token = "IgnoredToken000"', encoding="utf-8")

            result = ProjectScanner(AppConfig()).scan(root)

        self.assertEqual(result.stats.candidate_files, 1)
        self.assertEqual(result.stats.scanned_files, 1)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].relative_path, os.path.join("src", "app.py"))

    def test_size_binary_and_missing_file_protection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "large.py").write_bytes(b"x" * 1025)
            (root / "binary.py").write_bytes(b"text\x00binary")
            result = ProjectScanner(AppConfig(max_file_size_mb=1)).scan(root)

            self.assertFalse(is_probably_binary(b"print('ok')\n"))
            self.assertTrue(is_probably_binary(b"abc\x00def"))
            self.assertEqual(read_source_file(root / "missing.py"), (None, "read_error"))

        self.assertEqual(result.stats.scanned_files, 1)
        self.assertEqual(result.stats.skipped_files, 1)
        self.assertEqual(result.errors[0].error_type, "binary")

    def test_configured_file_size_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "large.py").write_bytes(b"x" * (1024 * 1024 + 1))
            result = ProjectScanner(AppConfig(max_file_size_mb=1)).scan(root)

        self.assertEqual(result.stats.scanned_files, 0)
        self.assertEqual(result.errors[0].error_type, "too_large")

    def test_utf8_bom_and_gbk_reading(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            utf8_path = root / "utf8.py"
            bom_path = root / "bom.py"
            gbk_path = root / "gbk.py"
            utf8_path.write_text("中文", encoding="utf-8")
            bom_path.write_text("带签名", encoding="utf-8-sig")
            gbk_path.write_bytes("中文内容".encode("gbk"))

            self.assertEqual(read_source_file(utf8_path), ("中文", None))
            self.assertEqual(read_source_file(bom_path), ("带签名", None))
            self.assertEqual(read_source_file(gbk_path), ("中文内容", None))

    def test_permission_and_decode_failures_are_isolated(self) -> None:
        with patch.object(Path, "open", side_effect=PermissionError):
            self.assertEqual(read_source_file(Path("blocked.py")), (None, "read_error"))

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.py"
            path.write_bytes(b"\x81")
            self.assertEqual(read_source_file(path), (None, "decode_error"))

    def test_invalid_root(self) -> None:
        with self.assertRaises(ValueError):
            ProjectScanner(AppConfig()).scan(Path("definitely-not-a-real-directory"))

    def test_symlink_is_not_followed_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.py"
            link = root / "linked.py"
            target.write_text('password = "DemoPassword"', encoding="utf-8")
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("当前 Windows 环境不允许创建符号链接")

            result = ProjectScanner(AppConfig()).scan(root)

        self.assertEqual(result.stats.scanned_files, 1)
        self.assertTrue(any(error.error_type == "symlink" for error in result.errors))

    def test_symlink_root_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            target = parent / "target"
            link = parent / "linked-root"
            target.mkdir()
            try:
                link.symlink_to(target, target_is_directory=True)
            except OSError:
                self.skipTest("当前 Windows 环境不允许创建目录符号链接")

            with self.assertRaises(ValueError):
                ProjectScanner(AppConfig()).scan(link)

    def test_demo_project_and_stable_order(self) -> None:
        root = Path(__file__).resolve().parent.parent / "demo_project"
        scanner = ProjectScanner(AppConfig())
        first = scanner.scan(root)
        second = scanner.scan(root)

        first_keys = [(item.severity, item.relative_path, item.line_number, item.rule_id) for item in first.findings]
        second_keys = [(item.severity, item.relative_path, item.line_number, item.rule_id) for item in second.findings]
        self.assertEqual(first_keys, second_keys)
        self.assertEqual(first.stats.scanned_files, 14)
        self.assertGreaterEqual(len(first.findings), 18)
        self.assertFalse(any(item.relative_path == "safe_demo.py" for item in first.findings))
        jwt_findings = [item for item in first.findings if item.relative_path == "jwt_demo.json"]
        self.assertEqual([item.risk_type for item in jwt_findings], ["JWT"])
        for finding in first.findings:
            self.assertNotIn("DemoPassword", finding.masked_value)

    def test_cli_output_is_masked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.joinpath("demo.py").write_text(
                'password = "DemoPasswordShouldStayHidden"',
                encoding="utf-8",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = run_cli_scan(AppConfig(), root, explain=True)

        self.assertEqual(exit_code, 0)
        self.assertIn("********", output.getvalue())
        self.assertIn("直接字符串赋值", output.getvalue())
        self.assertNotIn("DemoPasswordShouldStayHidden", output.getvalue())

    def test_moderate_project_performance_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index in range(200):
                root.joinpath(f"module_{index}.py").write_text(
                    f'constant_{index} = "ordinary-value-{index}"',
                    encoding="utf-8",
                )

            result = ProjectScanner(AppConfig()).scan(root)

        self.assertEqual(result.stats.scanned_files, 200)
        self.assertEqual(result.findings, [])
        self.assertLess(result.stats.duration_seconds, 5.0)

    def test_progress_and_cooperative_cancellation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index in range(20):
                root.joinpath(f"file_{index}.py").write_text(
                    'password = "DemoPassword"',
                    encoding="utf-8",
                )
            progress_events = []
            cancelled = False

            def on_progress(progress) -> None:
                nonlocal cancelled
                progress_events.append(progress)
                if progress.processed_files >= 3:
                    cancelled = True

            result = ProjectScanner(AppConfig()).scan(
                root,
                on_progress=on_progress,
                is_cancelled=lambda: cancelled,
            )

        self.assertEqual(result.stats.status, "cancelled")
        self.assertEqual(result.stats.candidate_files, 20)
        self.assertEqual(result.stats.scanned_files, 3)
        self.assertEqual(progress_events[-1].processed_files, 3)
        self.assertEqual(progress_events[-1].finding_count, 3)


if __name__ == "__main__":
    unittest.main()
