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
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from codeshield.models import ComparisonItem, Finding, ScanComparison, ScanHistoryRecord
from codeshield.ui.result_data import RISK_TYPE_LABELS, SEVERITY_COLORS, SEVERITY_LABELS


CHANGE_LABELS = {"new": "新增风险", "persistent": "持续风险", "resolved": "已消除风险"}
CHANGE_COLORS = {"new": "#b42318", "persistent": "#175cd3", "resolved": "#067647"}


class ComparisonPage(QWidget):
    finding_requested = Signal(object)

    def __init__(self) -> None:
        super().__init__()
        self.items: list[ComparisonItem] = []
        self.filtered_items: list[ComparisonItem] = []
        self._build_ui()
        self.set_no_baseline()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(12)
        title = QLabel("扫描对比")
        title.setObjectName("pageTitle")
        self.subtitle = QLabel("比较同一项目最近两次已完成扫描")
        self.subtitle.setObjectName("pageSubtitle")
        layout.addWidget(title)
        layout.addWidget(self.subtitle)

        summary = QFrame()
        summary.setObjectName("contentCard")
        summary_layout = QHBoxLayout(summary)
        self.summary_message = QLabel("暂无对比数据")
        self.summary_message.setObjectName("mutedText")
        summary_layout.addWidget(self.summary_message, 1)
        self.values: dict[str, QLabel] = {}
        for key, label in CHANGE_LABELS.items():
            block = QVBoxLayout()
            value = QLabel("0")
            value.setObjectName("smallStatValue")
            value.setStyleSheet(f"color: {CHANGE_COLORS[key]};")
            caption = QLabel(label)
            caption.setObjectName("mutedText")
            block.addWidget(value, 0, Qt.AlignmentFlag.AlignCenter)
            block.addWidget(caption, 0, Qt.AlignmentFlag.AlignCenter)
            summary_layout.addLayout(block)
            self.values[key] = value
        layout.addWidget(summary)

        toolbar = QFrame()
        toolbar.setObjectName("toolbarPanel")
        tools = QHBoxLayout(toolbar)
        self.search = QLineEdit()
        self.search.setPlaceholderText("搜索文件、风险类型或规则")
        self.change_filter = QComboBox()
        self.change_filter.addItem("全部变化", "")
        for key, label in CHANGE_LABELS.items():
            self.change_filter.addItem(label, key)
        self.type_filter = QComboBox()
        self.type_filter.addItem("全部类型", "")
        tools.addWidget(self.search, 1)
        tools.addWidget(self.change_filter)
        tools.addWidget(self.type_filter)
        layout.addWidget(toolbar)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(("变化", "等级", "风险类型", "文件", "行号", "评分"))
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(0, 105)
        self.table.setColumnWidth(1, 75)
        self.table.setColumnWidth(2, 150)
        self.table.setColumnWidth(3, 350)
        layout.addWidget(self.table, 1)
        hint = QLabel("双击风险项可在扫描结果页查看完整脱敏详情。白名单会影响最终结果差异，已消除不等同于已修复。")
        hint.setObjectName("mutedText")
        layout.addWidget(hint)

        self.search.textChanged.connect(self.apply_filters)
        self.change_filter.currentIndexChanged.connect(self.apply_filters)
        self.type_filter.currentIndexChanged.connect(self.apply_filters)
        self.table.cellDoubleClicked.connect(self._open_row)

    def set_comparison(
        self,
        current: ScanHistoryRecord,
        previous: ScanHistoryRecord,
        comparison: ScanComparison,
    ) -> None:
        self.subtitle.setText(
            f"{current.project_name} · 当前 {self._moment(current)} · 基线 {self._moment(previous)}"
        )
        self.summary_message.setText(
            f"本次新增 {comparison.new_count} 项，持续 {comparison.persistent_count} 项，"
            f"{comparison.resolved_count} 项已不再出现。"
        )
        self.values["new"].setText(str(comparison.new_count))
        self.values["persistent"].setText(str(comparison.persistent_count))
        self.values["resolved"].setText(str(comparison.resolved_count))
        self.items = [
            *(ComparisonItem("new", item) for item in comparison.new_findings),
            *(ComparisonItem("persistent", item) for item in comparison.persistent_findings),
            *(ComparisonItem("resolved", item) for item in comparison.resolved_findings),
        ]
        types = sorted({item.finding.risk_type for item in self.items})
        self.type_filter.blockSignals(True)
        self.type_filter.clear()
        self.type_filter.addItem("全部类型", "")
        for risk_type in types:
            self.type_filter.addItem(RISK_TYPE_LABELS.get(risk_type, risk_type), risk_type)
        self.type_filter.blockSignals(False)
        self.apply_filters()

    def set_no_baseline(self, project_name: str = "") -> None:
        self.items = []
        self.subtitle.setText(f"{project_name} · 首次完成扫描" if project_name else "比较同一项目最近两次已完成扫描")
        self.summary_message.setText("这是该项目首次完成扫描，暂无历史基线。")
        for value in self.values.values():
            value.setText("—")
        self.apply_filters()

    def apply_filters(self) -> None:
        keyword = self.search.text().strip().casefold()
        change = self.change_filter.currentData() or ""
        risk_type = self.type_filter.currentData() or ""
        self.filtered_items = [
            item for item in self.items
            if (not change or item.change == change)
            and (not risk_type or item.finding.risk_type == risk_type)
            and (
                not keyword
                or keyword in f"{item.finding.relative_path} {item.finding.risk_type} {item.finding.rule_name}".casefold()
            )
        ]
        self.table.setRowCount(len(self.filtered_items))
        for row, item in enumerate(self.filtered_items):
            finding = item.finding
            values = (
                CHANGE_LABELS[item.change],
                SEVERITY_LABELS.get(finding.severity, finding.severity),
                RISK_TYPE_LABELS.get(finding.risk_type, finding.risk_type),
                finding.relative_path,
                str(finding.line_number),
                str(finding.score),
            )
            for column, value in enumerate(values):
                cell = QTableWidgetItem(value)
                if column == 0:
                    cell.setForeground(QColor(CHANGE_COLORS[item.change]))
                    cell.setData(Qt.ItemDataRole.UserRole, finding)
                if column == 1:
                    background, foreground, _accent = SEVERITY_COLORS[finding.severity]
                    cell.setBackground(QColor(background))
                    cell.setForeground(QColor(foreground))
                if column in (0, 1, 4, 5):
                    cell.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.table.setItem(row, column, cell)

    def _open_row(self, row: int, _column: int) -> None:
        if 0 <= row < len(self.filtered_items):
            self.finding_requested.emit(self.filtered_items[row].finding)

    @staticmethod
    def _moment(record: ScanHistoryRecord) -> str:
        return (record.finished_at or record.started_at).strftime("%Y-%m-%d %H:%M:%S")
