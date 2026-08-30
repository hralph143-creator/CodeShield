import os
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QCoreApplication, QThread
from PySide6.QtWidgets import QApplication

from codeshield.config import AppConfig
from codeshield.ui.scan_worker import ScanWorker


class BrokenScanner:
    def __init__(self, _config) -> None:
        raise RuntimeError("internal details must not reach the UI")


class ScanWorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def test_completed_and_progress_signals(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.joinpath("app.py").write_text('password = "DemoPassword"', encoding="utf-8")
            worker = ScanWorker(AppConfig(), root)
            progress = []
            completed = []
            worker.progress.connect(progress.append)
            worker.completed.connect(completed.append)
            worker.run()

        self.assertTrue(progress)
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0].stats.status, "completed")

    def test_cancel_signal_returns_partial_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index in range(20):
                root.joinpath(f"file_{index}.py").write_text(
                    'password = "DemoPassword"', encoding="utf-8"
                )
            worker = ScanWorker(AppConfig(), root)
            cancelled = []
            worker.progress.connect(
                lambda progress: worker.request_cancel() if progress.processed_files >= 1 else None
            )
            worker.cancelled.connect(cancelled.append)
            worker.run()

        self.assertEqual(len(cancelled), 1)
        self.assertEqual(cancelled[0].stats.status, "cancelled")
        self.assertLess(cancelled[0].stats.scanned_files, 20)

    def test_failure_signal_is_readable(self) -> None:
        worker = ScanWorker(AppConfig(), Path("missing"), scanner_factory=BrokenScanner)
        failures = []
        worker.failed.connect(failures.append)
        worker.run()

        self.assertEqual(failures, ["扫描任务启动失败。"])
        self.assertNotIn("internal details", failures[0])

    def test_qthread_finishes_after_scan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.joinpath("app.py").write_text('password = "DemoPassword"', encoding="utf-8")
            thread = QThread()
            worker = ScanWorker(AppConfig(), root)
            worker.moveToThread(thread)
            thread.started.connect(worker.run)
            worker.completed.connect(thread.quit)
            worker.completed.connect(worker.deleteLater)
            thread.start()

            deadline = time.monotonic() + 3
            while thread.isRunning() and time.monotonic() < deadline:
                QCoreApplication.processEvents()
                time.sleep(0.005)
            thread.wait(1000)

        self.assertFalse(thread.isRunning())


if __name__ == "__main__":
    unittest.main()
