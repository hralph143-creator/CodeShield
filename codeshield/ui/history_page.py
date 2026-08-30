from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from codeshield.database import Database
from codeshield.ui.result_data import SEVERITY_COLORS


HISTORY_STATUS_LABELS = {
    "completed": "已完成",
    "cancelled": "已取消",
    "failed": "失败",
}


class HistoryPage(QWidget):
    open_requested = Signal(int)
    compare_requested = Signal(int)
    history_changed = Signal()

    def __init__(self, database: Database) -> None:
        super().__init__()
        self.database = database
        self.records = []
        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(14)
        title = QLabel("扫描历史")
        title.setObjectName("pageTitle")
        subtitle = QLabel("查看本机保存的历史扫描记录")
        subtitle.setObjectName("pageSubtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        toolbar = QFrame()
        toolbar.setObjectName("toolbarPanel")
        tools = QHBoxLayout(toolbar)
        self.search = QLineEdit()
        self.search.setPlaceholderText("搜索项目名称")
        self.status_filter = QComboBox()
        self.status_filter.addItem("全部状态", "")
        for value in ("completed", "cancelled", "failed"):
            self.status_filter.addItem(HISTORY_STATUS_LABELS[value], value)
        refresh_button = QPushButton("刷新")
        self.compare_button = QPushButton("与上次扫描比较")
        self.compare_button.setEnabled(False)
        self.delete_button = QPushButton("删除记录")
        tools.addWidget(self.search, 1)
        tools.addWidget(self.status_filter)
        tools.addWidget(refresh_button)
        tools.addWidget(self.compare_button)
        tools.addWidget(self.delete_button)
        layout.addWidget(toolbar)

        self.table = QTableWidget(0, 10)
        self.table.setHorizontalHeaderLabels(
            ("时间", "项目", "扫描文件", "风险总数", "严重", "高", "中", "低", "耗时", "状态")
        )
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(0, 155)
        self.table.setColumnWidth(1, 180)
        for column in range(2, 8):
            self.table.setColumnWidth(column, 72)
        self.table.setColumnWidth(8, 75)
        layout.addWidget(self.table, 1)

        self.search.textChanged.connect(self.refresh)
        self.status_filter.currentIndexChanged.connect(self.refresh)
        refresh_button.clicked.connect(self.refresh)
        self.delete_button.clicked.connect(self.delete_selected)
        self.compare_button.clicked.connect(self.compare_selected)
        self.table.cellDoubleClicked.connect(lambda row, _column: self.open_row(row))
        self.table.itemSelectionChanged.connect(self._update_compare_button)

    def refresh(self) -> None:
        self.records = self.database.list_scan_history(
            self.search.text(), self.status_filter.currentData() or ""
        )
        self.table.setRowCount(len(self.records))
        for row, record in enumerate(self.records):
            finished = record.finished_at or record.started_at
            values = (
                finished.strftime("%Y-%m-%d %H:%M:%S"),
                record.project_name,
                str(record.scanned_files),
                str(record.finding_count),
                str(record.critical_count),
                str(record.high_count),
                str(record.medium_count),
                str(record.low_count),
                f"{record.duration_ms / 1000:.2f}s",
                HISTORY_STATUS_LABELS.get(record.status, record.status),
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 1:
                    item.setToolTip(record.project_root)
                if column >= 2 and column != 9:
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                severity_by_column = {4: "critical", 5: "high", 6: "medium", 7: "low"}
                if column in severity_by_column:
                    _background, foreground, _accent = SEVERITY_COLORS[severity_by_column[column]]
                    item.setForeground(QColor(foreground))
                if column == 9:
                    status_color = {"completed": "#067647", "cancelled": "#B54708", "failed": "#C9363E"}.get(record.status, "#667085")
                    item.setForeground(QColor(status_color))
                self.table.setItem(row, column, item)
        self._update_compare_button()

    def open_row(self, row: int) -> None:
        if 0 <= row < len(self.records):
            self.open_requested.emit(self.records[row].scan_id)

    def delete_selected(self) -> None:
        row = self.table.currentRow()
        if not 0 <= row < len(self.records):
            return
        record = self.records[row]
        answer = QMessageBox.question(
            self,
            "删除扫描记录",
            f"确定删除“{record.project_name}”的这次扫描记录吗？",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.database.delete_scan(record.scan_id)
        self.refresh()
        self.history_changed.emit()

    def compare_selected(self) -> None:
        row = self.table.currentRow()
        if 0 <= row < len(self.records) and self.database.previous_completed_scan(self.records[row].scan_id):
            self.compare_requested.emit(self.records[row].scan_id)

    def _update_compare_button(self) -> None:
        row = self.table.currentRow()
        available = (
            0 <= row < len(self.records)
            and self.records[row].status == "completed"
            and self.database.previous_completed_scan(self.records[row].scan_id) is not None
        )
        self.compare_button.setEnabled(available)
        self.compare_button.setToolTip("" if available else "暂无可比较的历史扫描")
        selected = 0 <= row < len(self.records)
        self.delete_button.setEnabled(selected)
        self.delete_button.setToolTip("" if selected else "请先选择一条扫描记录")
