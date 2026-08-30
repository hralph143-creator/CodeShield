from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from threading import Event

from PySide6.QtCore import QObject, Signal, Slot

from codeshield.config import AppConfig
from codeshield.scanner import ProjectScanner


class ScanWorker(QObject):
    started = Signal()
    progress = Signal(object)
    completed = Signal(object)
    cancelled = Signal(object)
    failed = Signal(str)

    def __init__(
        self,
        config: AppConfig,
        scan_root: Path,
        scanner_factory: Callable[[AppConfig], ProjectScanner] = ProjectScanner,
    ) -> None:
        super().__init__()
        self.config = config
        self.scan_root = scan_root
        self.scanner_factory = scanner_factory
        self._cancel_requested = Event()

    @Slot()
    def run(self) -> None:
        self.started.emit()
        try:
            result = self.scanner_factory(self.config).scan(
                self.scan_root,
                on_progress=self.progress.emit,
                is_cancelled=self._cancel_requested.is_set,
            )
        except Exception as exc:
            if isinstance(exc, ValueError):
                message = "无法扫描所选目录，请检查路径和规则配置。"
            elif isinstance(exc, OSError):
                message = "扫描时无法访问文件系统。"
            else:
                message = "扫描任务启动失败。"
            self.failed.emit(message)
            return

        if result.stats.status == "cancelled":
            self.cancelled.emit(result)
        else:
            self.completed.emit(result)

    def request_cancel(self) -> None:
        # 事件可从 UI 线程直接设置，不依赖被扫描任务占用的 Worker 事件循环。
        self._cancel_requested.set()
