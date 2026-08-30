from __future__ import annotations

from dataclasses import replace
from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import QCoreApplication, QElapsedTimer, QThread, QTimer, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from codeshield.config import AppConfig
from codeshield.models import ScanProgress, ScanResult
from codeshield.ui.scan_worker import ScanWorker
from codeshield.scanner import ProjectScanner


STATE_LABELS = {
    "idle": "就绪",
    "scanning": "正在扫描",
    "cancelling": "正在取消",
    "completed": "扫描完成",
    "cancelled": "已取消",
    "failed": "扫描失败",
}


class ScanPage(QWidget):
    scan_completed = Signal(object)
    scan_cancelled = Signal(object)
    view_results_requested = Signal()
    state_changed = Signal(str)

    def __init__(
        self,
        config: AppConfig,
        scanner_factory: Callable[[AppConfig], ProjectScanner] = ProjectScanner,
    ) -> None:
        super().__init__()
        self.config = config
        self.scanner_factory = scanner_factory
        self.state = "idle"
        self.thread: QThread | None = None
        self.worker: ScanWorker | None = None
        self.has_results = False
        self.elapsed = QElapsedTimer()
        self.elapsed_timer = QTimer(self)
        self.elapsed_timer.setInterval(250)
        self.elapsed_timer.timeout.connect(self._update_elapsed)
        self._build_ui()
        self._set_state("idle")

    def _build_ui(self) -> None:
        page_layout = QVBoxLayout(self)
        page_layout.setContentsMargins(32, 28, 32, 28)
        page_layout.setSpacing(14)

        title = QLabel("项目扫描")
        title.setObjectName("pageTitle")
        subtitle = QLabel("选择本地代码目录，使用当前规则和风险评分引擎进行离线扫描")
        subtitle.setObjectName("pageSubtitle")
        page_layout.addWidget(title)
        page_layout.addWidget(subtitle)

        setup_panel = QFrame()
        setup_panel.setObjectName("contentCard")
        setup_layout = QVBoxLayout(setup_panel)
        setup_layout.setSpacing(14)
        setup_layout.addWidget(self._card_title("扫描目标与配置"))
        path_row = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setReadOnly(True)
        self.path_edit.setPlaceholderText("请选择需要扫描的本地项目目录")
        self.select_button = QPushButton("选择项目")
        self.select_button.setObjectName("secondaryButton")
        self.select_button.clicked.connect(self.choose_directory)
        path_row.addWidget(self.path_edit, 1)
        path_row.addWidget(self.select_button)
        setup_layout.addLayout(path_row)

        config_layout = QGridLayout()
        config_layout.setHorizontalSpacing(18)
        config_layout.setVerticalSpacing(8)
        config_layout.addWidget(QLabel("单文件上限"), 0, 0)
        self.size_spin = QSpinBox()
        self.size_spin.setRange(1, 100)
        self.size_spin.setSuffix(" MB")
        self.size_spin.setValue(self.config.max_file_size_mb)
        config_layout.addWidget(self.size_spin, 0, 1)
        self.personal_info_check = QCheckBox("检测邮箱、手机号和身份证号")
        self.personal_info_check.setChecked(self.config.detect_personal_info)
        config_layout.addWidget(self.personal_info_check, 0, 2, 1, 2)
        extensions = QLabel(f"文件类型：{len(self.config.included_extensions)} 项")
        ignored = QLabel(f"忽略目录：{len(self.config.ignored_dirs)} 项")
        extensions.setObjectName("mutedText")
        ignored.setObjectName("mutedText")
        config_layout.addWidget(extensions, 0, 4)
        config_layout.addWidget(ignored, 0, 5)
        config_layout.setColumnStretch(3, 1)
        setup_layout.addLayout(config_layout)
        page_layout.addWidget(setup_panel)

        action_row = QHBoxLayout()
        self.start_button = QPushButton("开始扫描")
        self.start_button.setObjectName("primaryButton")
        self.start_button.setMinimumWidth(120)
        self.start_button.clicked.connect(self.start_scan)
        self.cancel_button = QPushButton("取消扫描")
        self.cancel_button.setObjectName("dangerButton")
        self.cancel_button.clicked.connect(self.cancel_scan)
        self.view_button = QPushButton("查看扫描结果")
        self.view_button.setObjectName("secondaryButton")
        self.view_button.clicked.connect(self.view_results_requested)
        action_row.addWidget(self.start_button)
        action_row.addWidget(self.cancel_button)
        action_row.addStretch()
        action_row.addWidget(self.view_button)
        page_layout.addLayout(action_row)

        status_card = QFrame()
        status_card.setObjectName("surfacePanel")
        status_layout = QGridLayout(status_card)
        status_layout.setContentsMargins(18, 14, 18, 14)
        status_layout.setHorizontalSpacing(24)
        self.status_value = self._stat_value("就绪")
        self.file_value = self._stat_value("0 / 0")
        self.finding_value = self._stat_value("0")
        self.error_value = self._stat_value("0")
        self.elapsed_value = self._stat_value("00:00")
        for column, (caption, value) in enumerate((
            ("扫描状态", self.status_value),
            ("文件进度", self.file_value),
            ("发现风险", self.finding_value),
            ("读取失败", self.error_value),
            ("扫描耗时", self.elapsed_value),
        )):
            label = QLabel(caption)
            label.setObjectName("statCaption")
            status_layout.addWidget(label, 0, column)
            status_layout.addWidget(value, 1, column)
        status_layout.setColumnStretch(0, 1)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_label = QLabel("0%")
        self.progress_label.setObjectName("mutedText")
        progress_row = QHBoxLayout()
        progress_row.addWidget(self.progress_bar, 1)
        progress_row.addWidget(self.progress_label)
        self.current_file = QLabel("当前文件：—")
        self.current_file.setObjectName("mutedText")
        self.current_file.setToolTip("当前文件：—")
        status_layout.addLayout(progress_row, 2, 0, 1, 5)
        status_layout.addWidget(self.current_file, 3, 0, 1, 5)
        page_layout.addWidget(status_card)

        self.notice = QLabel("请选择需要扫描的本地项目目录。")
        self.notice.setObjectName("noticeText")
        self.notice.setWordWrap(True)
        page_layout.addWidget(self.notice)
        privacy_note = QLabel("扫描完成后结果会写入本地历史数据库；分析全程离线，原始敏感值不会写入历史记录。")
        privacy_note.setObjectName("mutedText")
        privacy_note.setWordWrap(True)
        page_layout.addWidget(privacy_note)
        page_layout.addStretch()

    def choose_directory(self) -> None:
        selected = QFileDialog.getExistingDirectory(self, "选择要扫描的项目")
        if selected:
            self.set_project_path(Path(selected))

    def set_project_path(self, path: Path) -> None:
        self.path_edit.setText(str(path))
        self.path_edit.setCursorPosition(0)
        self.notice.setText("目录已选择，可以开始扫描。")
        self._update_controls()

    def start_scan(self) -> None:
        if self.thread is not None and self.thread.isRunning():
            self.notice.setText("已有扫描任务正在运行。")
            return
        scan_root = Path(self.path_edit.text().strip())
        if not self.path_edit.text().strip():
            self.notice.setText("请先选择需要扫描的项目目录。")
            return
        if not scan_root.exists() or not scan_root.is_dir():
            self.notice.setText("所选项目目录不存在或无法访问。")
            return

        task_config = replace(
            self.config,
            max_file_size_mb=self.size_spin.value(),
            detect_personal_info=self.personal_info_check.isChecked(),
        )
        self.thread = QThread(self)
        self.worker = ScanWorker(task_config, scan_root, self.scanner_factory)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._on_progress)
        self.worker.completed.connect(self._on_completed)
        self.worker.cancelled.connect(self._on_cancelled)
        self.worker.failed.connect(self._on_failed)
        for signal in (self.worker.completed, self.worker.cancelled, self.worker.failed):
            signal.connect(self.thread.quit)
            signal.connect(self.worker.deleteLater)
        self.thread.finished.connect(self._thread_finished)
        self.thread.finished.connect(self.thread.deleteLater)

        self.has_results = False
        self._reset_progress()
        self.elapsed.start()
        self.elapsed_timer.start()
        self._set_state("scanning")
        self.notice.setText("正在准备候选文件，请稍候……")
        self.thread.start()

    def cancel_scan(self) -> None:
        if self.worker is None or self.state not in {"scanning", "cancelling"}:
            return
        self.worker.request_cancel()
        self._set_state("cancelling")
        self.notice.setText("已请求取消，当前文件处理完成后停止。")

    def _on_progress(self, progress: ScanProgress) -> None:
        if progress.phase == "preparing":
            self.progress_bar.setRange(0, 0)
            self.progress_label.setText("准备中")
            return
        self.progress_bar.setRange(0, max(progress.candidate_files, 1))
        self.progress_bar.setValue(progress.processed_files)
        percent = round(progress.processed_files / max(progress.candidate_files, 1) * 100)
        self.progress_label.setText(f"{percent}%")
        self.file_value.setText(f"{progress.processed_files} / {progress.candidate_files}")
        self.finding_value.setText(str(progress.finding_count))
        self.error_value.setText(str(progress.read_errors))
        current = progress.current_file or "—"
        self.current_file.setText(f"当前文件：{self._middle_elide(current)}")
        self.current_file.setToolTip(f"当前文件：{current}")
        self.notice.setText("正在执行规则、上下文、熵值和结构验证。")

    def _on_completed(self, result: ScanResult) -> None:
        self.elapsed_timer.stop()
        self.has_results = True
        self._set_state("completed")
        self.progress_label.setText("100%")
        self._show_result_summary(result)
        self.scan_completed.emit(result)

    def _on_cancelled(self, result: ScanResult) -> None:
        self.elapsed_timer.stop()
        self._set_state("cancelled")
        self.notice.setText(
            f"扫描已取消，已扫描 {result.stats.scanned_files} 个文件；取消摘要已保存，"
            "当前完成结果保持不变。"
        )
        self.scan_cancelled.emit(result)

    def _on_failed(self, message: str) -> None:
        self.elapsed_timer.stop()
        self._set_state("failed")
        self.notice.setText(message)

    def _thread_finished(self) -> None:
        self.thread = None
        self.worker = None
        self._update_controls()

    def _show_result_summary(self, result: ScanResult) -> None:
        counts = {level: 0 for level in ("critical", "high", "medium", "low")}
        for finding in result.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        self.notice.setText(
            f"扫描完成：{result.stats.scanned_files} 个文件，{len(result.findings)} 项风险；"
            f"严重 {counts['critical']}，高 {counts['high']}，中 {counts['medium']}，低 {counts['low']}；"
            f"读取失败 {result.stats.read_errors}。"
        )

    def _set_state(self, state: str) -> None:
        self.state = state
        self.status_value.setText(STATE_LABELS[state])
        self._update_controls()
        self.state_changed.emit(state)

    def _update_controls(self) -> None:
        busy = self.state in {"scanning", "cancelling"}
        if self.thread is not None and self.thread.isRunning() and self.state in {"completed", "cancelled", "failed"}:
            busy = True
        path = Path(self.path_edit.text().strip()) if self.path_edit.text().strip() else None
        has_valid_path = path is not None and path.exists() and path.is_dir()
        self.start_button.setEnabled(not busy and has_valid_path)
        self.start_button.setToolTip("" if has_valid_path else "请先选择有效的项目目录")
        self.select_button.setEnabled(not busy)
        self.size_spin.setEnabled(not busy)
        self.personal_info_check.setEnabled(not busy)
        self.cancel_button.setEnabled(self.state == "scanning")
        self.view_button.setEnabled(self.has_results and not busy)

    def _reset_progress(self) -> None:
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_label.setText("0%")
        self.file_value.setText("0 / 0")
        self.finding_value.setText("0")
        self.error_value.setText("0")
        self.elapsed_value.setText("00:00")
        self.current_file.setText("当前文件：—")
        self.current_file.setToolTip("当前文件：—")

    def _update_elapsed(self) -> None:
        if not self.elapsed.isValid():
            return
        seconds = self.elapsed.elapsed() // 1000
        self.elapsed_value.setText(f"{seconds // 60:02d}:{seconds % 60:02d}")

    def shutdown(self, timeout_ms: int = 5000) -> bool:
        if self.worker is not None:
            self.worker.request_cancel()
        if self.thread is not None and self.thread.isRunning():
            thread = self.thread
            thread.quit()
            wait_timer = QElapsedTimer()
            wait_timer.start()
            while thread.isRunning() and wait_timer.elapsed() < timeout_ms:
                QCoreApplication.processEvents()
                thread.wait(20)
            return not thread.isRunning()
        return True

    @staticmethod
    def _card_title(text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("cardTitle")
        return label

    @staticmethod
    def _stat_value(text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("smallStatValue")
        return label

    @staticmethod
    def _middle_elide(value: str, limit: int = 92) -> str:
        if len(value) <= limit:
            return value
        side = (limit - 1) // 2
        return f"{value[:side]}…{value[-side:]}"
