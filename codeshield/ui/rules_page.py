from __future__ import annotations

import re
import sqlite3

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from codeshield.database import Database
from codeshield.models import ManagedRule
from codeshield.rules import validate_rule_pattern
from codeshield.ui.result_data import RISK_TYPE_LABELS, SEVERITY_COLORS, SEVERITY_LABELS


LANGUAGES = ("python", "java", "javascript", "typescript", "c", "cpp", "r", "rust", "config")


class RuleDialog(QDialog):
    def __init__(self, rule: ManagedRule | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("编辑自定义规则" if rule else "新增自定义规则")
        self.setMinimumSize(560, 520)
        layout = QFormLayout(self)
        self.name = QLineEdit(rule.name if rule else "")
        self.risk_type = QComboBox()
        for value in ("Password", "API Key", "Secret", "Token", "Private Key", "Database Credential"):
            self.risk_type.addItem(RISK_TYPE_LABELS.get(value, value), value)
        self.pattern = QPlainTextEdit(rule.pattern if rule else "")
        self.pattern.setPlaceholderText(r"必须使用命名组，例如：token\s*=\s*['\"](?P<value>[^'\"]+)['\"]")
        self.pattern.setMaximumHeight(120)
        self.severity = QComboBox()
        for value in ("critical", "high", "medium", "low"):
            self.severity.addItem(SEVERITY_LABELS[value], value)
        self.score = QSpinBox()
        self.score.setRange(0, 100)
        self.score.setValue(rule.score if rule else 40)
        self.language = QComboBox()
        self.language.addItem("全部", "all")
        for value in LANGUAGES:
            self.language.addItem(value, value)
        self.description = QLineEdit(rule.description if rule else "")
        self.suggestion = QLineEdit(rule.suggestion if rule else "")
        self.enabled = QCheckBox("启用")
        self.enabled.setChecked(rule.enabled if rule else True)
        if rule:
            self.risk_type.setCurrentIndex(max(0, self.risk_type.findData(rule.risk_type)))
            self.severity.setCurrentIndex(max(0, self.severity.findData(rule.severity)))
            language = rule.languages[0] if len(rule.languages) == 1 else "all"
            self.language.setCurrentIndex(max(0, self.language.findData(language)))
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Save
        )
        buttons.accepted.connect(self._validate)
        buttons.rejected.connect(self.reject)
        layout.addRow("规则名称", self.name)
        layout.addRow("风险类型", self.risk_type)
        layout.addRow("正则表达式", self.pattern)
        layout.addRow("默认等级", self.severity)
        layout.addRow("基础分数", self.score)
        layout.addRow("适用语言", self.language)
        layout.addRow("检测说明", self.description)
        layout.addRow("修复建议", self.suggestion)
        layout.addRow("状态", self.enabled)
        layout.addRow(buttons)

    def _validate(self) -> None:
        if not self.name.text().strip():
            QMessageBox.warning(self, "无法保存", "请输入规则名称。")
            return
        try:
            validate_rule_pattern(self.pattern.toPlainText())
        except (re.error, ValueError) as exc:
            QMessageBox.warning(self, "正则表达式无效", str(exc))
            return
        self.accept()

    def languages(self) -> list[str]:
        selected = self.language.currentData()
        return list(LANGUAGES) if selected == "all" else [selected]


class RulesPage(QWidget):
    changed = Signal()

    def __init__(self, database: Database, embedded: bool = False) -> None:
        super().__init__()
        self.database = database
        self.embedded = embedded
        self.rules: list[ManagedRule] = []
        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        if self.embedded:
            layout.setContentsMargins(0, 10, 0, 0)
        else:
            layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(10 if self.embedded else 12)
        if not self.embedded:
            title = QLabel("检测规则")
            title.setObjectName("pageTitle")
            subtitle = QLabel("管理内置和自定义静态检测规则")
            subtitle.setObjectName("pageSubtitle")
            layout.addWidget(title)
            layout.addWidget(subtitle)

        toolbar = QFrame()
        toolbar.setObjectName("toolbarPanel")
        tools = QHBoxLayout(toolbar)
        self.search = QLineEdit()
        self.search.setPlaceholderText("搜索规则名称或风险类型")
        self.source_filter = QComboBox()
        self.source_filter.addItem("全部来源", "")
        self.source_filter.addItem("内置", "builtin")
        self.source_filter.addItem("自定义", "custom")
        add_button = QPushButton("新增自定义规则")
        add_button.setObjectName("primaryButton")
        self.edit_button = QPushButton("编辑")
        self.toggle_button = QPushButton("启用 / 禁用")
        self.delete_button = QPushButton("删除")
        tools.addWidget(self.search, 1)
        tools.addWidget(self.source_filter)
        tools.addWidget(add_button)
        tools.addWidget(self.edit_button)
        tools.addWidget(self.toggle_button)
        tools.addWidget(self.delete_button)
        layout.addWidget(toolbar)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(("名称", "风险类型", "等级", "语言", "来源", "状态"))
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(0, 240)
        self.table.setColumnWidth(1, 150)
        self.table.setColumnWidth(2, 80)
        self.table.setColumnWidth(3, 240)
        self.table.setColumnWidth(4, 80)
        self.empty_label = QLabel("暂无检测规则。请检查内置规则文件或新增自定义规则。")
        self.empty_label.setObjectName("emptyText")
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_label.setMinimumHeight(30)
        layout.addWidget(self.empty_label)
        layout.addWidget(self.table, 1)

        self.search.textChanged.connect(self.refresh)
        self.source_filter.currentIndexChanged.connect(self.refresh)
        add_button.clicked.connect(self.add_rule)
        self.edit_button.clicked.connect(self.edit_selected)
        self.toggle_button.clicked.connect(self.toggle_selected)
        self.delete_button.clicked.connect(self.delete_selected)
        self.table.itemSelectionChanged.connect(self._update_actions)

    def refresh(self) -> None:
        term = self.search.text().strip().casefold()
        source = self.source_filter.currentData() or ""
        try:
            rules = self.database.list_managed_rules()
        except (sqlite3.Error, OSError, ValueError):
            rules = []
            self.empty_label.setText("检测规则加载失败，请检查规则文件和本地数据库。（RULE-001）")
        else:
            self.empty_label.setText("暂无检测规则。请检查内置规则文件或新增自定义规则。")
        self.rules = [
            rule for rule in rules
            if (not term or term in f"{rule.name} {rule.risk_type} {rule.rule_id}".casefold())
            and (not source or (source == "builtin") == rule.builtin)
        ]
        self.table.setRowCount(len(self.rules))
        self.empty_label.setVisible(not self.rules)
        self.table.setVisible(True)
        for row, rule in enumerate(self.rules):
            languages = "全部" if set(rule.languages) == set(LANGUAGES) else ", ".join(rule.languages)
            values = (
                rule.name,
                RISK_TYPE_LABELS.get(rule.risk_type, rule.risk_type),
                SEVERITY_LABELS.get(rule.severity, rule.severity),
                languages,
                "内置" if rule.builtin else "自定义",
                "已启用" if rule.enabled else "已禁用",
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column in (2, 4, 5):
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                if column == 2:
                    background, foreground, _accent = SEVERITY_COLORS[rule.severity]
                    item.setBackground(QColor(background))
                    item.setForeground(QColor(foreground))
                if column == 5:
                    item.setForeground(QColor("#067647" if rule.enabled else "#667085"))
                self.table.setItem(row, column, item)
        self._update_actions()

    def add_rule(self) -> None:
        dialog = RuleDialog(parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._save_dialog(dialog)

    def edit_selected(self) -> None:
        rule = self._selected_rule()
        if rule is None:
            QMessageBox.information(self, "尚未选择规则", "请先在表格中选择一条自定义规则。")
            return
        if rule.builtin:
            QMessageBox.information(self, "内置规则", "内置规则只允许启用或禁用。")
            return
        dialog = RuleDialog(rule, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._save_dialog(dialog, rule.rule_id)

    def _save_dialog(self, dialog: RuleDialog, rule_id: str | None = None) -> None:
        try:
            self.database.save_custom_rule(
                dialog.name.text(),
                dialog.risk_type.currentData(),
                dialog.pattern.toPlainText(),
                dialog.severity.currentData(),
                dialog.score.value(),
                dialog.languages(),
                dialog.description.text(),
                dialog.suggestion.text(),
                dialog.enabled.isChecked(),
                rule_id,
            )
        except (ValueError, re.error) as exc:
            QMessageBox.warning(self, "无法保存规则", str(exc))
            return
        self.refresh()
        self.changed.emit()

    def toggle_selected(self) -> None:
        rule = self._selected_rule()
        if rule is None:
            QMessageBox.information(self, "尚未选择规则", "请先在表格中选择一条检测规则。")
            return
        if rule.builtin:
            self.database.set_builtin_rule_enabled(rule.rule_id, not rule.enabled)
        else:
            self.database.set_custom_rule_enabled(rule.rule_id, not rule.enabled)
        self.refresh()
        self.changed.emit()

    def delete_selected(self) -> None:
        rule = self._selected_rule()
        if rule is None:
            QMessageBox.information(self, "尚未选择规则", "请先在表格中选择一条自定义规则。")
            return
        if rule.builtin:
            QMessageBox.information(self, "内置规则", "内置规则不能删除。")
            return
        if QMessageBox.question(self, "删除规则", f"确定删除“{rule.name}”吗？") != QMessageBox.StandardButton.Yes:
            return
        self.database.delete_custom_rule(rule.rule_id)
        self.refresh()
        self.changed.emit()

    def _selected_rule(self) -> ManagedRule | None:
        row = self.table.currentRow()
        return self.rules[row] if 0 <= row < len(self.rules) else None

    def _update_actions(self) -> None:
        rule = self._selected_rule()
        self.toggle_button.setEnabled(True)
        self.edit_button.setEnabled(True)
        self.delete_button.setEnabled(True)
        message = "请先选择一条规则" if rule is None else "内置规则不能编辑或删除" if rule.builtin else ""
        self.edit_button.setToolTip(message)
        self.delete_button.setToolTip(message)
