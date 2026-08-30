from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from codeshield.comparison import compare_scans
from codeshield.database import Database
from codeshield.reporting import export_report


class ReportsPage(QWidget):
    exported = Signal(str)

    def __init__(self, database: Database) -> None:
        super().__init__()
        self.database = database
        self.records = []
        self.last_output: Path | None = None
        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(14)
        title = QLabel("报告中心")
        title.setObjectName("pageTitle")
        subtitle = QLabel("导出本机扫描结果与风险分析报告")
        subtitle.setObjectName("pageSubtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        card = QFrame()
        card.setObjectName("contentCard")
        card.setMaximumWidth(820)
        form = QFormLayout(card)
        form.setContentsMargins(24, 22, 24, 24)
        form.setSpacing(14)
        self.scan_combo = QComboBox()
        self.report_type = QComboBox()
        self.report_type.addItem("HTML 离线报告", "html")
        self.report_type.addItem("JSON 数据报告", "json")
        summary_row = QHBoxLayout()
        self.summary_values: dict[str, QLabel] = {}
        colors = {"critical": "#C9363E", "high": "#B76400", "medium": "#8A6800", "low": "#245FB8"}
        for key, caption in (("critical", "严重"), ("high", "高"), ("medium", "中"), ("low", "低")):
            label = QLabel(f"{caption} 0")
            label.setStyleSheet(f"color: {colors[key]}; font-weight: 600;")
            summary_row.addWidget(label)
            self.summary_values[key] = label
        summary_row.addStretch()
        output_row = QHBoxLayout()
        self.output_dir = QLineEdit()
        self.output_dir.setPlaceholderText("选择报告输出目录")
        self.choose_button = QPushButton("选择目录")
        output_row.addWidget(self.output_dir, 1)
        output_row.addWidget(self.choose_button)
        action_row = QHBoxLayout()
        self.export_button = QPushButton("导出报告")
        self.export_button.setObjectName("primaryButton")
        self.open_button = QPushButton("打开所在文件夹")
        self.open_button.setEnabled(False)
        action_row.addWidget(self.export_button)
        action_row.addWidget(self.open_button)
        action_row.addStretch()
        self.notice = QLabel("报告只使用数据库中的脱敏快照，不会重新读取源码。")
        self.notice.setObjectName("mutedText")
        self.notice.setWordWrap(True)
        form.addRow("扫描记录", self.scan_combo)
        form.addRow("风险摘要", summary_row)
        form.addRow("报告类型", self.report_type)
        form.addRow("输出目录", output_row)
        form.addRow("", action_row)
        form.addRow("", self.notice)
        layout.addWidget(card)
        layout.addStretch()

        self.choose_button.clicked.connect(self.choose_directory)
        self.export_button.clicked.connect(self.export_selected)
        self.open_button.clicked.connect(self.open_output_directory)
        self.scan_combo.currentIndexChanged.connect(self._update_summary)
        self.output_dir.textChanged.connect(self._update_export_button)

    def refresh(self) -> None:
        selected_id = self.scan_combo.currentData() if self.scan_combo.count() else None
        self.records = self.database.list_scan_history(status="completed")
        self.scan_combo.clear()
        for record in self.records:
            moment = record.finished_at or record.started_at
            self.scan_combo.addItem(
                f"{record.project_name} · {moment:%Y-%m-%d %H:%M:%S} · {record.finding_count} 项风险",
                record.scan_id,
            )
        if selected_id is not None:
            index = self.scan_combo.findData(selected_id)
            if index >= 0:
                self.scan_combo.setCurrentIndex(index)
        available = bool(self.records)
        self.scan_combo.setEnabled(available)
        self.notice.setText(
            "报告只使用数据库中的脱敏快照，不会重新读取源码。"
            if available else "暂无可导出的扫描记录。完成一次扫描后再导出报告。"
        )
        self._update_summary()
        self._update_export_button()

    def choose_directory(self) -> None:
        selected = QFileDialog.getExistingDirectory(self, "选择报告输出目录", self.output_dir.text())
        if selected:
            self.output_dir.setText(selected)
            self.output_dir.setCursorPosition(0)

    def select_scan(self, scan_id: int) -> None:
        index = self.scan_combo.findData(scan_id)
        if index >= 0:
            self.scan_combo.setCurrentIndex(index)

    def export_selected(self) -> None:
        scan_id = self.scan_combo.currentData()
        directory = Path(self.output_dir.text().strip())
        if scan_id is None:
            self.notice.setText("暂无可导出的扫描记录。")
            return
        if not directory.is_dir():
            QMessageBox.warning(self, "无法导出", "请选择有效的输出目录。")
            return
        try:
            record = next(item for item in self.records if item.scan_id == scan_id)
            current = self.database.load_scan_result(scan_id)
            previous_record = self.database.previous_completed_scan(scan_id)
            comparison = None
            if previous_record:
                previous = self.database.load_scan_result(previous_record.scan_id)
                comparison = compare_scans(
                    previous_record.scan_id,
                    previous.findings,
                    scan_id,
                    current.findings,
                )
            target = export_report(
                directory,
                self.report_type.currentData(),
                record,
                current,
                comparison,
            )
        except (OSError, ValueError, KeyError) as exc:
            QMessageBox.warning(self, "报告导出失败", str(exc))
            return
        self.last_output = target
        self.open_button.setEnabled(True)
        self.notice.setText(f"报告已导出：{target.name}")
        self.exported.emit(str(target))

    def open_output_directory(self) -> None:
        if self.last_output:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.last_output.parent)))

    def _update_summary(self) -> None:
        scan_id = self.scan_combo.currentData()
        record = next((item for item in self.records if item.scan_id == scan_id), None)
        values = {
            "critical": record.critical_count if record else 0,
            "high": record.high_count if record else 0,
            "medium": record.medium_count if record else 0,
            "low": record.low_count if record else 0,
        }
        captions = {"critical": "严重", "high": "高", "medium": "中", "low": "低"}
        for key, label in self.summary_values.items():
            label.setText(f"{captions[key]} {values[key]}")

    def _update_export_button(self) -> None:
        has_scan = self.scan_combo.currentData() is not None
        directory_text = self.output_dir.text().strip()
        has_directory = bool(directory_text) and Path(directory_text).is_dir()
        self.export_button.setEnabled(has_scan and has_directory)
        if not has_scan:
            message = "暂无可导出的扫描记录"
        elif not has_directory:
            message = "请先选择有效的输出目录"
        else:
            message = ""
        self.export_button.setToolTip(message)
