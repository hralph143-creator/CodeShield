from __future__ import annotations

from dataclasses import replace

from PySide6.QtCore import QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from codeshield.config import AppConfig, ConfigStore, SCAN_MODE_LABELS, SCAN_MODES


class SettingsPage(QWidget):
    config_saved = Signal(object)

    def __init__(self, config: AppConfig, store: ConfigStore) -> None:
        super().__init__()
        self.config = config
        self.store = store
        self._build_ui()
        self.load_config(config)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(12)
        title = QLabel("设置")
        title.setObjectName("pageTitle")
        subtitle = QLabel("管理默认扫描行为与本地数据位置")
        subtitle.setObjectName("pageSubtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        scan_card = QFrame()
        scan_card.setObjectName("contentCard")
        scan_form = QFormLayout(scan_card)
        self.mode_combo = QComboBox()
        for mode in SCAN_MODES:
            self.mode_combo.addItem(SCAN_MODE_LABELS[mode], mode)
        self.size_spin = QSpinBox()
        self.size_spin.setRange(1, 100)
        self.size_spin.setSuffix(" MB")
        self.personal_info = QCheckBox("检测邮箱、手机号和身份证号")
        scan_form.addRow("默认扫描模式", self.mode_combo)
        scan_form.addRow("默认单文件上限", self.size_spin)
        scan_form.addRow("个人信息检测", self.personal_info)
        layout.addWidget(scan_card)

        data_card = QFrame()
        data_card.setObjectName("contentCard")
        data_layout = QVBoxLayout(data_card)
        path = QLabel(str(self.store.data_dir))
        path.setObjectName("mutedText")
        path.setWordWrap(True)
        data_actions = QHBoxLayout()
        open_data = QPushButton("打开数据目录")
        open_logs = QPushButton("打开日志目录")
        data_actions.addWidget(open_data)
        data_actions.addWidget(open_logs)
        data_actions.addStretch()
        data_layout.addWidget(QLabel("本地数据目录"))
        data_layout.addWidget(path)
        data_layout.addLayout(data_actions)
        layout.addWidget(data_card)

        actions = QHBoxLayout()
        self.save_button = QPushButton("保存设置")
        self.save_button.setObjectName("primaryButton")
        self.reset_button = QPushButton("恢复默认扫描设置")
        actions.addWidget(self.save_button)
        actions.addWidget(self.reset_button)
        actions.addStretch()
        self.notice = QLabel("设置只影响扫描配置，不会删除历史、白名单或自定义规则。")
        self.notice.setObjectName("noticeText")
        layout.addLayout(actions)
        layout.addWidget(self.notice)
        layout.addStretch()

        self.save_button.clicked.connect(self.save)
        self.reset_button.clicked.connect(lambda: self.load_config(AppConfig()))
        open_data.clicked.connect(lambda: self._open_dir(self.store.data_dir))
        open_logs.clicked.connect(lambda: self._open_dir(self.store.data_dir / "logs"))

    def load_config(self, config: AppConfig) -> None:
        self.mode_combo.setCurrentIndex(max(0, self.mode_combo.findData(config.scan_mode)))
        self.size_spin.setValue(config.max_file_size_mb)
        self.personal_info.setChecked(config.detect_personal_info)

    def save(self) -> None:
        updated = replace(
            self.config,
            scan_mode=self.mode_combo.currentData(),
            max_file_size_mb=self.size_spin.value(),
            detect_personal_info=self.personal_info.isChecked(),
        )
        try:
            self.store.save(updated)
        except OSError:
            self.notice.setText("无法保存设置，请检查本地数据目录权限。")
            return
        self.config = updated
        self.notice.setText("扫描设置已保存。历史、白名单和规则未受影响。")
        self.config_saved.emit(updated)

    def _open_dir(self, path) -> None:
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError:
            QMessageBox.warning(self, "无法打开目录", "目录无法创建或访问，请检查当前用户权限。")
            return
        if not QDesktopServices.openUrl(QUrl.fromLocalFile(str(path))):
            QMessageBox.warning(self, "无法打开目录", "系统无法打开该目录，请手动前往设置中显示的路径。")
