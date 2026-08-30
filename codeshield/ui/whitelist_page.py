from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
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


TYPE_LABELS = {
    "fingerprint": "风险指纹",
    "file": "文件路径",
    "directory": "目录路径",
    "rule": "检测规则",
}


class WhitelistDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("新增白名单")
        self.setMinimumWidth(430)
        layout = QFormLayout(self)
        self.entry_type = QComboBox()
        for value in ("file", "directory", "rule"):
            self.entry_type.addItem(TYPE_LABELS[value], value)
        self.value = QLineEdit()
        self.value.setPlaceholderText("相对文件路径、目录前缀或 rule_id")
        self.description = QLineEdit()
        self.description.setPlaceholderText("说明这条白名单的用途")
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Save
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow("类型", self.entry_type)
        layout.addRow("目标", self.value)
        layout.addRow("备注", self.description)
        layout.addRow(buttons)


class WhitelistPage(QWidget):
    changed = Signal()

    def __init__(self, database: Database) -> None:
        super().__init__()
        self.database = database
        self.entries = []
        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(14)
        title = QLabel("白名单")
        title.setObjectName("pageTitle")
        subtitle = QLabel("管理已确认的误报和忽略规则")
        subtitle.setObjectName("pageSubtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        toolbar = QFrame()
        toolbar.setObjectName("toolbarPanel")
        tools = QHBoxLayout(toolbar)
        self.search = QLineEdit()
        self.search.setPlaceholderText("搜索目标或备注")
        self.type_filter = QComboBox()
        self.type_filter.addItem("全部类型", "")
        for value, label in TYPE_LABELS.items():
            self.type_filter.addItem(label, value)
        add_button = QPushButton("新增")
        add_button.setObjectName("primaryButton")
        self.toggle_button = QPushButton("启用 / 禁用")
        self.delete_button = QPushButton("删除")
        tools.addWidget(self.search, 1)
        tools.addWidget(self.type_filter)
        tools.addWidget(add_button)
        tools.addWidget(self.toggle_button)
        tools.addWidget(self.delete_button)
        layout.addWidget(toolbar)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(("类型", "目标", "备注", "创建时间", "状态"))
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(0, 110)
        self.table.setColumnWidth(1, 260)
        self.table.setColumnWidth(2, 260)
        self.table.setColumnWidth(3, 155)
        layout.addWidget(self.table, 1)

        self.search.textChanged.connect(self.refresh)
        self.type_filter.currentIndexChanged.connect(self.refresh)
        add_button.clicked.connect(self.add_manual)
        self.toggle_button.clicked.connect(self.toggle_selected)
        self.delete_button.clicked.connect(self.delete_selected)
        self.table.itemSelectionChanged.connect(self._update_actions)

    def refresh(self) -> None:
        term = self.search.text().strip().casefold()
        entry_type = self.type_filter.currentData() or ""
        entries = self.database.list_whitelist()
        self.entries = [
            entry
            for entry in entries
            if (not entry_type or entry.entry_type == entry_type)
            and (not term or term in f"{entry.value} {entry.description}".casefold())
        ]
        self.table.setRowCount(len(self.entries))
        for row, entry in enumerate(self.entries):
            target = self._display_value(entry.entry_type, entry.value)
            values = (
                TYPE_LABELS.get(entry.entry_type, entry.entry_type),
                target,
                entry.description or "—",
                entry.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "已启用" if entry.enabled else "已禁用",
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 1:
                    item.setToolTip(entry.value)
                if column in (0, 4):
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                if column == 4:
                    item.setForeground(QColor("#067647" if entry.enabled else "#667085"))
                self.table.setItem(row, column, item)
        self._update_actions()

    @staticmethod
    def _display_value(entry_type: str, value: str) -> str:
        if entry_type == "fingerprint" and len(value) > 16:
            return f"{value[:8]}…{value[-6:]}"
        return value

    def add_manual(self) -> None:
        dialog = WhitelistDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self.database.add_whitelist(
                dialog.entry_type.currentData(), dialog.value.text(), dialog.description.text()
            )
        except ValueError as exc:
            QMessageBox.warning(self, "无法添加", str(exc))
            return
        self.refresh()
        self.changed.emit()

    def toggle_selected(self) -> None:
        entry = self._selected_entry()
        if entry is None:
            return
        self.database.set_whitelist_enabled(entry.entry_id, not entry.enabled)
        self.refresh()
        self.changed.emit()

    def delete_selected(self) -> None:
        entry = self._selected_entry()
        if entry is None:
            return
        if QMessageBox.question(self, "删除白名单", "确定删除选中的白名单吗？") != QMessageBox.StandardButton.Yes:
            return
        self.database.delete_whitelist(entry.entry_id)
        self.refresh()
        self.changed.emit()

    def _selected_entry(self):
        row = self.table.currentRow()
        return self.entries[row] if 0 <= row < len(self.entries) else None

    def _update_actions(self) -> None:
        selected = self._selected_entry() is not None
        self.toggle_button.setEnabled(selected)
        self.delete_button.setEnabled(selected)
        message = "" if selected else "请先选择一条白名单记录"
        self.toggle_button.setToolTip(message)
        self.delete_button.setToolTip(message)
