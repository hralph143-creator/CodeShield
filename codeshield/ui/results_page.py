from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QFrame,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from codeshield.models import Finding, ScanResult
from codeshield.ui.result_data import (
    RISK_TYPE_LABELS,
    SEVERITY_LABELS,
    STATUS_LABELS,
    STATUS_COLORS,
    SEVERITY_COLORS,
    detail_data,
    filter_findings,
)


class ResultsPage(QWidget):
    status_change_requested = Signal(object, str)
    whitelist_requested = Signal(object)
    comparison_requested = Signal()

    def __init__(self) -> None:
        super().__init__()
        self.findings: list[Finding] = []
        self.filtered_findings: list[Finding] = []
        self.current_finding: Finding | None = None
        self._build_ui()
        self.set_result(None)

    def _build_ui(self) -> None:
        page_layout = QVBoxLayout(self)
        page_layout.setContentsMargins(28, 24, 28, 24)
        page_layout.setSpacing(12)

        title = QLabel("扫描结果")
        title.setObjectName("pageTitle")
        subtitle = QLabel("筛选风险项，并查看脱敏上下文与评分依据")
        subtitle.setObjectName("pageSubtitle")
        page_layout.addWidget(title)
        page_layout.addWidget(subtitle)

        filter_card = QFrame()
        filter_card.setObjectName("toolbarPanel")
        filters = QHBoxLayout(filter_card)
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("搜索文件、风险类型或规则")
        self.severity_combo = QComboBox()
        self.severity_combo.addItem("全部等级", "")
        for value in ("critical", "high", "medium", "low"):
            self.severity_combo.addItem(SEVERITY_LABELS[value], value)
        self.type_combo = QComboBox()
        self.language_combo = QComboBox()
        self.count_label = QLabel("显示 0 / 0")
        self.count_label.setObjectName("mutedText")
        filters.addWidget(self.search_edit, 1)
        filters.addWidget(self.severity_combo)
        filters.addWidget(self.type_combo)
        filters.addWidget(self.language_combo)
        filters.addWidget(self.count_label)
        page_layout.addWidget(filter_card)

        self.search_edit.textChanged.connect(self.apply_filters)
        self.severity_combo.currentIndexChanged.connect(self.apply_filters)
        self.type_combo.currentIndexChanged.connect(self.apply_filters)
        self.language_combo.currentIndexChanged.connect(self.apply_filters)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        table_card = QFrame()
        table_card.setObjectName("surfacePanel")
        table_layout = QVBoxLayout(table_card)
        self.summary_label = QLabel("暂无扫描结果")
        self.summary_label.setObjectName("noticeText")
        self.summary_label.setWordWrap(True)
        summary_row = QHBoxLayout()
        summary_row.addWidget(self.summary_label, 1)
        self.compare_button = QPushButton("查看变化")
        self.compare_button.setVisible(False)
        summary_row.addWidget(self.compare_button)
        table_layout.addLayout(summary_row)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(("等级", "风险类型", "文件", "行号", "评分", "脱敏内容", "状态"))
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        header = self.table.horizontalHeader()
        header.setMinimumSectionSize(36)
        for column in (0, 1, 3, 4, 6):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.table.currentCellChanged.connect(self._show_selected)
        table_layout.addWidget(self.table, 1)
        splitter.addWidget(table_card)

        detail_card = QFrame()
        detail_card.setObjectName("surfacePanel")
        detail_card.setMinimumWidth(340)
        detail_card.setMaximumWidth(410)
        detail_layout = QVBoxLayout(detail_card)
        self.detail_title = QLabel("风险详情")
        self.detail_title.setObjectName("cardTitle")
        self.detail_meta = QLabel("选择左侧风险项查看详情")
        self.detail_meta.setObjectName("mutedText")
        self.detail_meta.setWordWrap(True)
        action_row = QHBoxLayout()
        self.status_combo = QComboBox()
        for value in ("unresolved", "confirmed", "false_positive", "ignored", "fixed"):
            self.status_combo.addItem(STATUS_LABELS[value], value)
        self.whitelist_button = QPushButton("加入白名单")
        action_row.addWidget(self.status_combo, 1)
        action_row.addWidget(self.whitelist_button)

        utility_row = QHBoxLayout()
        utility_row.setSpacing(8)
        self.copy_button = QPushButton("复制脱敏摘要")
        self.copy_button.setToolTip("复制当前风险的脱敏信息，不包含原始敏感值")
        self.open_location_button = QPushButton("打开文件位置")
        self.open_location_button.setToolTip("在文件资源管理器中打开源文件所在目录")
        utility_row.addWidget(self.copy_button)
        utility_row.addWidget(self.open_location_button)
        self.masked_value = QLabel("—")
        self.masked_value.setObjectName("maskedValue")
        self.masked_value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        detail_layout.addWidget(self.detail_title)
        detail_layout.addWidget(self.detail_meta)
        detail_layout.addLayout(action_row)
        detail_layout.addLayout(utility_row)
        detail_layout.addWidget(self._section_label("脱敏内容"))
        detail_layout.addWidget(self.masked_value)
        detail_layout.addWidget(self._section_label("检测依据"))
        self.factors = QTableWidget(0, 2)
        self.factors.horizontalHeader().setVisible(False)
        self.factors.verticalHeader().setVisible(False)
        self.factors.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.factors.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.factors.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.factors.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.factors.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.factors.setShowGrid(False)
        self.factors.setMaximumHeight(170)
        detail_layout.addWidget(self.factors)
        detail_layout.addWidget(self._section_label("脱敏上下文"))
        self.context = QPlainTextEdit()
        self.context.setReadOnly(True)
        self.context.setMaximumHeight(90)
        self.context.setObjectName("codeContext")
        detail_layout.addWidget(self.context)
        detail_layout.addWidget(self._section_label("修复建议"))
        self.suggestion = QLabel("—")
        self.suggestion.setWordWrap(True)
        detail_layout.addWidget(self.suggestion)
        detail_layout.addStretch()
        splitter.addWidget(detail_card)
        splitter.setSizes((720, 380))
        page_layout.addWidget(splitter, 1)
        self.status_combo.currentIndexChanged.connect(self._request_status_change)
        self.whitelist_button.clicked.connect(self._request_whitelist)
        self.copy_button.clicked.connect(self._copy_masked_summary)
        self.open_location_button.clicked.connect(self._open_file_location)
        self.compare_button.clicked.connect(self.comparison_requested.emit)

    def set_result(self, result: ScanResult | None) -> None:
        self.findings = result.findings if result else []
        self._fill_dynamic_filter(
            self.type_combo,
            "全部类型",
            sorted({item.risk_type for item in self.findings}),
            RISK_TYPE_LABELS,
        )
        self._fill_dynamic_filter(self.language_combo, "全部语言", sorted({item.language for item in self.findings}))
        if result is None:
            self.summary_label.setText("暂无扫描结果。请先在“项目扫描”页面选择本地代码目录并执行扫描。")
        elif not result.findings:
            self.summary_label.setText(
                f"本次扫描未发现符合当前检测规则的风险项。扫描文件 {result.stats.scanned_files} 个，"
                f"耗时 {result.stats.duration_seconds:.2f} 秒。"
            )
        else:
            self.summary_label.setText(
                f"扫描文件 {result.stats.scanned_files} 个，发现 {len(result.findings)} 项风险，"
                f"耗时 {result.stats.duration_seconds:.2f} 秒。"
            )
        self.apply_filters()

    def set_comparison_available(self, available: bool, text: str = "") -> None:
        self.compare_button.setVisible(available)
        self.compare_button.setToolTip(text)

    def apply_filters(self) -> None:
        self.filtered_findings = filter_findings(
            self.findings,
            keyword=self.search_edit.text(),
            severity=self.severity_combo.currentData() or "",
            risk_type=self.type_combo.currentData() or "",
            language=self.language_combo.currentData() or "",
        )
        self.table.setRowCount(0)
        for finding in self.filtered_findings:
            row = self.table.rowCount()
            self.table.insertRow(row)
            severity_item = QTableWidgetItem(SEVERITY_LABELS.get(finding.severity, finding.severity))
            background, foreground, _accent = SEVERITY_COLORS.get(
                finding.severity, ("#f2f4f7", "#344054", "#98A2B3")
            )
            severity_item.setBackground(QColor(background))
            severity_item.setForeground(QColor(foreground))
            severity_item.setData(Qt.ItemDataRole.UserRole, finding)
            file_item = QTableWidgetItem(finding.relative_path)
            file_item.setToolTip(finding.file_path)
            status_item = QTableWidgetItem(STATUS_LABELS.get(finding.status, finding.status))
            status_item.setForeground(QColor(STATUS_COLORS.get(finding.status, "#667085")))
            items = (
                severity_item,
                QTableWidgetItem(RISK_TYPE_LABELS.get(finding.risk_type, finding.risk_type)),
                file_item,
                QTableWidgetItem(str(finding.line_number)),
                QTableWidgetItem(str(finding.score)),
                QTableWidgetItem(finding.masked_value),
                status_item,
            )
            for column, item in enumerate(items):
                if column in (3, 4):
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.table.setItem(row, column, item)
        self.count_label.setText(f"显示 {len(self.filtered_findings)} / {len(self.findings)}")
        if self.filtered_findings:
            self.table.selectRow(0)
        else:
            self._clear_detail()

    def _show_selected(self, row: int, _column: int, _old_row: int, _old_column: int) -> None:
        item = self.table.item(row, 0) if row >= 0 else None
        finding = item.data(Qt.ItemDataRole.UserRole) if item else None
        if finding is None:
            self._clear_detail()
            return
        self.current_finding = finding
        data = detail_data(finding)
        self.detail_title.setText(f"{data['severity']}风险 · {data['risk_type']} · {data['score']}")
        _background, foreground, _accent = SEVERITY_COLORS.get(
            finding.severity, ("#f2f4f7", "#344054", "#98A2B3")
        )
        self.detail_title.setStyleSheet(f"color: {foreground};")
        self.detail_meta.setText(
            f"来源：{data['source']}\n规则：{data['rule']}\n语言：{data['language']}\n"
            f"文件：{data['file']}\n位置：{data['location']}\n信息熵：{data['entropy']}"
        )
        self.status_combo.blockSignals(True)
        index = self.status_combo.findData(finding.status)
        self.status_combo.setCurrentIndex(max(0, index))
        self.status_combo.blockSignals(False)
        self.status_combo.setEnabled(finding.database_id is not None)
        self.whitelist_button.setEnabled(True)
        self.masked_value.setText(str(data["masked_value"]))
        self._show_factors(finding)
        self.context.setPlainText(str(data["context"]))
        self.suggestion.setText(str(data["suggestion"]))

    def _clear_detail(self) -> None:
        self.current_finding = None
        self.detail_title.setText("风险详情")
        self.detail_title.setStyleSheet("")
        self.detail_meta.setText("选择左侧风险项查看详情")
        self.masked_value.setText("—")
        self.factors.setRowCount(0)
        self.context.clear()
        self.suggestion.setText("—")
        self.status_combo.setEnabled(False)
        self.whitelist_button.setEnabled(True)

    def _request_status_change(self) -> None:
        if self.current_finding is not None and self.status_combo.isEnabled():
            self.status_change_requested.emit(self.current_finding, self.status_combo.currentData())

    def _request_whitelist(self) -> None:
        if self.current_finding is None:
            QMessageBox.information(self, "尚未选择风险", "请先在扫描结果表格中选择一条风险。")
            return
        if not self.current_finding.fingerprint:
            QMessageBox.information(self, "无法加入白名单", "当前风险没有可用指纹，无法加入白名单。")
            return
        self.whitelist_requested.emit(self.current_finding)

    def _copy_masked_summary(self) -> None:
        finding = self.current_finding
        if finding is None:
            QMessageBox.information(self, "尚未选择风险", "请先在扫描结果表格中选择一条风险。")
            return
        summary = (
            f"{SEVERITY_LABELS.get(finding.severity, finding.severity)}风险 · "
            f"{RISK_TYPE_LABELS.get(finding.risk_type, finding.risk_type)} · 评分 {finding.score}\n"
            f"文件：{finding.relative_path}:{finding.line_number}:{finding.column}\n"
            f"脱敏内容：{finding.masked_value}\n"
            f"修复建议：{finding.suggestion}"
        )
        QApplication.clipboard().setText(summary)
        QMessageBox.information(self, "已复制", "风险脱敏摘要已复制到剪贴板。")

    def _open_file_location(self) -> None:
        finding = self.current_finding
        if finding is None:
            QMessageBox.information(self, "尚未选择风险", "请先在扫描结果表格中选择一条风险。")
            return
        file_path = Path(finding.file_path)
        if not file_path.exists() or not file_path.is_file():
            QMessageBox.warning(self, "源文件不可用", "源文件已移动、删除或当前无法访问。")
            return
        if not QDesktopServices.openUrl(QUrl.fromLocalFile(str(file_path.parent))):
            QMessageBox.warning(self, "无法打开目录", "系统未能打开源文件所在目录。")

    def update_finding_status(self, database_id: int, status: str) -> None:
        from dataclasses import replace

        self.findings = [
            replace(finding, status=status) if finding.database_id == database_id else finding
            for finding in self.findings
        ]
        self.apply_filters()

    @staticmethod
    def _fill_dynamic_filter(
        combo: QComboBox,
        label: str,
        values: list[str],
        display_labels: dict[str, str] | None = None,
    ) -> None:
        combo.blockSignals(True)
        combo.clear()
        combo.addItem(label, "")
        for value in values:
            combo.addItem((display_labels or {}).get(value, value), value)
        combo.blockSignals(False)

    def _show_factors(self, finding: Finding) -> None:
        self.factors.setRowCount(len(finding.risk_factors))
        for row, factor in enumerate(finding.risk_factors):
            detail_item = QTableWidgetItem(factor.detail)
            score_item = QTableWidgetItem(f"{factor.points:+d}")
            score_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            score_item.setForeground(QColor("#067647" if factor.points >= 0 else "#b42318"))
            self.factors.setItem(row, 0, detail_item)
            self.factors.setItem(row, 1, score_item)
        self.factors.resizeRowsToContents()

    @staticmethod
    def _section_label(text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("detailSection")
        return label
