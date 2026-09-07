from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QColor, QCloseEvent, QPalette
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QGraphicsDropShadowEffect,
    QGridLayout,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from codeshield.bootstrap import Runtime
from codeshield.comparison import compare_scans
from codeshield.models import Finding, ScanResult
from codeshield.ui.comparison_page import ComparisonPage
from codeshield.ui.icons import (
    app_icon,
    app_icon_pixmap,
    configure_windows_app_id,
    icon_pixmap,
)
from codeshield.ui.history_page import HistoryPage
from codeshield.ui.results_page import ResultsPage
from codeshield.ui.reports_page import ReportsPage
from codeshield.ui.rules_page import RulesPage
from codeshield.ui.scan_page import STATE_LABELS, ScanPage
from codeshield.ui.settings_page import SettingsPage
from codeshield.ui.styles import APP_STYLE, CRITICAL, HIGH, LOW, MEDIUM, PRIMARY
from codeshield.ui.whitelist_page import WhitelistPage
from codeshield.version import APP_DISPLAY_VERSION


NAV_ITEMS = [
    ("概览", "overview"),
    ("项目扫描", "scan"),
    ("扫描结果", "results"),
    ("扫描历史", "history"),
    ("检测规则", "rules"),
    ("报告中心", "reports"),
    ("设置", "settings"),
]

NAV_COLOR_IDLE = "#667382"
NAV_COLOR_ACTIVE = PRIMARY


class MainWindow(QMainWindow):
    def __init__(self, runtime: Runtime) -> None:
        configure_windows_app_id()
        super().__init__()
        self.runtime = runtime
        self.pages: dict[str, QWidget] = {}
        self.overview_values: dict[str, QLabel] = {}
        self.current_scan_result: ScanResult | None = None
        self.current_comparison_scan_id: int | None = None
        self.setWindowTitle(f"CodeShield {APP_DISPLAY_VERSION} - 代码敏感信息扫描器")
        self.setWindowIcon(app_icon())
        self.setMinimumSize(1100, 720)
        self.resize(1280, 800)
        self.setStyleSheet(APP_STYLE)
        self.setCentralWidget(self._build_content())
        self._polish_data_views()
        self._apply_panel_shadows()
        self._apply_palette()

    def _build_content(self) -> QWidget:
        content = QWidget()
        content.setObjectName("applicationShell")
        layout = QHBoxLayout(content)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(216)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(14, 20, 14, 18)
        sidebar_layout.setSpacing(0)

        brand_row = QHBoxLayout()
        brand_row.setSpacing(10)
        brand_icon = QLabel()
        brand_icon.setObjectName("brandIcon")
        brand_icon.setPixmap(app_icon_pixmap(34))
        brand_row.addWidget(brand_icon)

        brand_text = QVBoxLayout()
        brand_text.setSpacing(0)
        brand = QLabel("CodeShield")
        brand.setObjectName("brand")
        subtitle = QLabel("本地代码安全扫描")
        subtitle.setObjectName("brandSubtitle")
        brand_text.addWidget(brand)
        brand_text.addWidget(subtitle)
        brand_row.addLayout(brand_text)
        brand_row.addStretch()
        sidebar_layout.addLayout(brand_row)
        sidebar_layout.addSpacing(24)

        self.navigation = QListWidget()
        self.navigation.setObjectName("navigation")
        self.navigation.setSpacing(2)
        self.navigation.setIconSize(QSize(20, 20))
        self.navigation.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._nav_kinds = [key for _, key in NAV_ITEMS]
        for title, key in NAV_ITEMS:
            item = QListWidgetItem(icon_pixmap(key, NAV_COLOR_IDLE, 20), title)
            item.setSizeHint(QSize(0, 44))
            item.setData(Qt.ItemDataRole.UserRole, key)
            self.navigation.addItem(item)
        self.navigation.currentRowChanged.connect(self._on_nav_changed)
        sidebar_layout.addWidget(self.navigation, 1)

        version = QLabel(f"CodeShield {APP_DISPLAY_VERSION} · 本地离线模式")
        version.setObjectName("phaseLabel")
        sidebar_layout.addWidget(version)

        self.stack = QStackedWidget()
        self.stack.setObjectName("workspace")
        self.scan_page = ScanPage(self.runtime.config, self.runtime.create_scanner)
        self.results_page = ResultsPage()
        self.history_page = HistoryPage(self.runtime.database)
        self.comparison_page = ComparisonPage()
        self.rules_page = RulesPage(self.runtime.database, embedded=True)
        self.whitelist_page = WhitelistPage(self.runtime.database, embedded=True)
        self.rule_management_page = self._rule_management_page()
        self.reports_page = ReportsPage(self.runtime.database)
        self.settings_page = SettingsPage(self.runtime.config, self.runtime.config_store)
        self.scan_page.scan_completed.connect(self._handle_scan_completed)
        self.scan_page.scan_cancelled.connect(self._handle_scan_cancelled)
        self.scan_page.view_results_requested.connect(self._show_results)
        self.history_page.open_requested.connect(self._open_history)
        self.history_page.compare_requested.connect(self._show_comparison)
        self.history_page.history_changed.connect(self._refresh_overview)
        self.history_page.history_changed.connect(self.reports_page.refresh)
        self.results_page.status_change_requested.connect(self._change_finding_status)
        self.results_page.whitelist_requested.connect(self._add_finding_to_whitelist)
        self.results_page.comparison_requested.connect(self._show_current_comparison)
        self.comparison_page.finding_requested.connect(self._open_comparison_finding)
        self.scan_page.state_changed.connect(
            lambda state: self.statusBar().showMessage(STATE_LABELS.get(state, state))
        )
        self.settings_page.config_saved.connect(self._apply_config)
        self.rules_page.changed.connect(self._refresh_overview)
        self.whitelist_page.changed.connect(self._refresh_overview)
        builders: dict[str, Callable[[], QWidget]] = {
            "overview": self._overview_page,
            "scan": lambda: self.scan_page,
            "results": lambda: self.results_page,
            "history": lambda: self.history_page,
            "rules": lambda: self.rule_management_page,
            "reports": lambda: self.reports_page,
            "settings": lambda: self.settings_page,
        }
        for _, key in NAV_ITEMS:
            page = builders[key]()
            self._configure_page_surface(page)
            self.pages[key] = page
            self.stack.addWidget(page)
        self._configure_page_surface(self.comparison_page)
        self.stack.addWidget(self.comparison_page)

        layout.addWidget(sidebar)
        layout.addWidget(self.stack, 1)
        self.navigation.setCurrentRow(0)
        self.statusBar().showMessage("就绪")
        self._refresh_overview()
        return content

    def _rule_management_page(self) -> QWidget:
        page, body = self._page_shell("检测规则", "统一管理检测规则与误报白名单")
        self.rule_management_tabs = QTabWidget()
        self.rule_management_tabs.setObjectName("managementTabs")
        self.rule_management_tabs.addTab(self.rules_page, "规则管理")
        self.rule_management_tabs.addTab(self.whitelist_page, "白名单")
        body.addWidget(self.rule_management_tabs, 1)
        return page

    def _overview_page(self) -> QWidget:
        page, body = self._page_shell("概览", "查看本机已完成扫描的累计数据")
        body.setContentsMargins(28, 18, 28, 18)
        body.setSpacing(10)
        counts = self.runtime.database.dashboard_counts()

        summary = QFrame()
        summary.setObjectName("summaryStrip")
        summary.setMinimumHeight(88)
        summary.setMaximumHeight(96)
        summary_layout = QHBoxLayout(summary)
        summary_layout.setContentsMargins(18, 12, 18, 12)
        summary_layout.setSpacing(0)
        for key, caption, value, icon_kind in (
            ("scans", "累计扫描项目", counts["scans"], "folder"),
            ("files", "累计扫描文件", counts["files"], "file"),
            ("findings", "累计发现风险", counts["findings"], "risk"),
            ("critical", "严重风险", counts["critical"], "critical"),
        ):
            cell, number = self._summary_metric(caption, value, icon_kind)
            self.overview_values[key] = number
            summary_layout.addWidget(cell, 1)
            if key != "critical":
                divider = QFrame()
                divider.setObjectName("metricDivider")
                divider.setFixedWidth(1)
                divider.setMinimumHeight(46)
                summary_layout.addWidget(divider)
        body.addWidget(summary)

        body.addWidget(self._recent_card())
        body.addWidget(self._activity_card())
        body.addWidget(self._operations_card(), 1)
        return page

    def _summary_metric(self, caption: str, value: int, icon_kind: str) -> tuple[QWidget, QLabel]:
        cell = QWidget()
        cell.setObjectName("summaryMetric")
        layout = QHBoxLayout(cell)
        layout.setContentsMargins(16, 4, 16, 4)
        layout.setSpacing(12)

        icon_label = QLabel()
        icon_label.setObjectName("metricIcon")
        icon_label.setFixedSize(34, 34)
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setPixmap(icon_pixmap(icon_kind, "#4F6F89", 18))
        layout.addWidget(icon_label)

        text = QVBoxLayout()
        text.setSpacing(2)
        caption_label = QLabel(caption)
        caption_label.setObjectName("statCaption")
        number = QLabel(str(value))
        number.setObjectName("statNumber")
        if icon_kind == "critical":
            number.setStyleSheet("color: #C9363E;")
        text.addWidget(caption_label)
        text.addWidget(number)
        layout.addLayout(text)
        layout.addStretch()
        return cell, number

    def _recent_card(self) -> QWidget:
        card = QFrame()
        card.setObjectName("recentStrip")
        card.setMinimumHeight(78)
        card.setMaximumHeight(90)

        layout = QHBoxLayout(card)
        layout.setContentsMargins(20, 14, 20, 14)
        layout.setSpacing(16)

        header = QHBoxLayout()
        header.setSpacing(9)
        header_icon = QLabel()
        header_icon.setPixmap(icon_pixmap("history", "#667085", 18))
        header_title = QLabel("最近扫描")
        header_title.setObjectName("cardTitle")
        header.addWidget(header_icon)
        header.addWidget(header_title)
        header.addStretch()
        layout.addLayout(header)

        divider = QFrame()
        divider.setObjectName("metricDivider")
        divider.setFixedWidth(1)
        divider.setMinimumHeight(42)
        layout.addWidget(divider)

        scan_info = QVBoxLayout()
        scan_info.setSpacing(4)
        message = QLabel("还没有扫描记录。完成首次项目扫描后，最近扫描和风险分布会显示在这里。")
        message.setObjectName("recentPrimary")
        message.setWordWrap(True)
        self.recent_message = message
        scan_info.addWidget(message)
        empty_text = QLabel("暂无记录")
        empty_text.setObjectName("emptyText")
        self.recent_detail = empty_text
        scan_info.addWidget(empty_text)
        layout.addLayout(scan_info, 1)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        self.rescan_latest_button = QPushButton("重新扫描")
        self.rescan_latest_button.setToolTip("载入最近一次扫描的项目目录")
        self.open_latest_button = QPushButton("查看结果")
        self.open_latest_button.setObjectName("primaryButton")
        self.open_latest_button.setToolTip("打开最近一次扫描的风险结果")
        self.rescan_latest_button.clicked.connect(self._load_latest_scan_path)
        self.open_latest_button.clicked.connect(self._open_latest_result)
        actions.addWidget(self.rescan_latest_button)
        actions.addWidget(self.open_latest_button)
        layout.addLayout(actions)
        return card

    def _activity_card(self) -> QWidget:
        card = QFrame()
        card.setObjectName("contentCard")
        card.setMinimumHeight(190)
        card.setMaximumHeight(240)
        layout = QHBoxLayout(card)
        layout.setContentsMargins(20, 14, 20, 14)
        layout.setSpacing(24)

        distribution = QVBoxLayout()
        distribution.addWidget(self._card_title("累计风险等级分布"))
        self.severity_bars: dict[str, tuple[QProgressBar, QLabel]] = {}
        for key, label in (("critical", "严重"), ("high", "高"), ("medium", "中"), ("low", "低")):
            row = QHBoxLayout()
            name = QLabel(label)
            name.setFixedWidth(36)
            bar = QProgressBar()
            bar.setTextVisible(False)
            color = {"critical": CRITICAL, "high": HIGH, "medium": MEDIUM, "low": LOW}[key]
            bar.setStyleSheet(f"QProgressBar::chunk {{ background: {color}; }}")
            value = QLabel("0")
            value.setFixedWidth(34)
            value.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            row.addWidget(name)
            row.addWidget(bar, 1)
            row.addWidget(value)
            distribution.addLayout(row)
            self.severity_bars[key] = (bar, value)
        distribution.addStretch()
        layout.addLayout(distribution, 1)

        recent = QVBoxLayout()
        recent.addWidget(self._card_title("最近完成扫描"))
        self.recent_table = QTableWidget(0, 3)
        self.recent_table.setHorizontalHeaderLabels(("项目", "风险", "时间"))
        self.recent_table.verticalHeader().setVisible(False)
        self.recent_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.recent_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.recent_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.recent_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.recent_table.setMaximumHeight(160)
        recent.addWidget(self.recent_table)
        layout.addLayout(recent, 2)
        return card

    def _operations_card(self) -> QWidget:
        card = QFrame()
        card.setObjectName("contentCard")
        card.setMinimumHeight(170)
        layout = QHBoxLayout(card)
        layout.setContentsMargins(20, 14, 20, 14)
        layout.setSpacing(24)

        processing = QVBoxLayout()
        processing.setSpacing(8)
        processing.addWidget(self._card_title("扫描处理概况"))
        metrics = QGridLayout()
        metrics.setHorizontalSpacing(28)
        metrics.setVerticalSpacing(8)
        self.operational_values: dict[str, QLabel] = {}
        for index, (key, caption) in enumerate((
            ("candidates", "累计候选文件"),
            ("skipped", "累计跳过文件"),
            ("errors", "累计读取失败"),
            ("suppressed", "白名单抑制"),
            ("rules", "当前启用规则"),
            ("whitelist", "启用白名单"),
        )):
            metric = QWidget()
            metric_layout = QVBoxLayout(metric)
            metric_layout.setContentsMargins(0, 0, 0, 0)
            metric_layout.setSpacing(2)
            value = QLabel("0")
            value.setObjectName("operationalNumber")
            caption_label = QLabel(caption)
            caption_label.setObjectName("statCaption")
            metric_layout.addWidget(value)
            metric_layout.addWidget(caption_label)
            metrics.addWidget(metric, index // 3, index % 3)
            self.operational_values[key] = value
        processing.addLayout(metrics)
        processing.addStretch()
        layout.addLayout(processing, 1)

        divider = QFrame()
        divider.setObjectName("metricDivider")
        divider.setFixedWidth(1)
        layout.addWidget(divider)

        languages = QVBoxLayout()
        languages.setSpacing(8)
        language_header = QHBoxLayout()
        language_header.addWidget(self._card_title("最近项目语言构成"))
        self.language_context = QLabel("暂无语言统计")
        self.language_context.setObjectName("mutedText")
        language_header.addStretch()
        language_header.addWidget(self.language_context)
        languages.addLayout(language_header)
        self.language_table = QTableWidget(0, 3)
        self.language_table.setHorizontalHeaderLabels(("语言", "文件数", "占比"))
        self.language_table.verticalHeader().setVisible(False)
        self.language_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.language_table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.language_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.language_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.language_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        languages.addWidget(self.language_table, 1)
        layout.addLayout(languages, 1)
        return card

    @staticmethod
    def _card_title(text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("cardTitle")
        return label

    def _on_nav_changed(self, row: int) -> None:
        for index, kind in enumerate(self._nav_kinds):
            color = NAV_COLOR_ACTIVE if index == row else NAV_COLOR_IDLE
            self.navigation.item(index).setIcon(icon_pixmap(kind, color, 20))
        self._show_page(row)

    def _apply_config(self, config) -> None:
        self.runtime.config = config
        self.scan_page.set_config(config)
        self.statusBar().showMessage("扫描设置已保存")

    @staticmethod
    def _page_shell(title: str, subtitle: str) -> tuple[QWidget, QVBoxLayout]:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)
        heading = QLabel(title)
        heading.setObjectName("pageTitle")
        description = QLabel(subtitle)
        description.setObjectName("pageSubtitle")
        layout.addWidget(heading)
        layout.addWidget(description)
        return page, layout

    def _show_page(self, row: int) -> None:
        if row >= 0:
            self._set_stack_page(self.stack.widget(row))

    @staticmethod
    def _configure_page_surface(page: QWidget) -> None:
        """Ensure hidden stack pages can never bleed through during repaints."""
        page.setObjectName("pageSurface")
        page.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        page.setAutoFillBackground(True)
        palette = page.palette()
        palette.setColor(QPalette.ColorRole.Window, QColor("#F4F5F7"))
        page.setPalette(palette)

    def _set_stack_page(self, page: QWidget | None) -> None:
        if page is None:
            return
        current = self.stack.currentWidget()
        if current is page:
            page.update()
            return
        if current is not None:
            current.hide()
        self.stack.setCurrentWidget(page)
        page.show()
        page.raise_()
        self.stack.repaint()

    def _handle_scan_completed(self, result: ScanResult) -> None:
        history_saved = True
        try:
            self.runtime.database.save_scan_result(result)
        except Exception:
            history_saved = False
        else:
            self.history_page.refresh()
            self.reports_page.refresh()
            self.reports_page.select_scan(result.scan_id)
            self._refresh_overview()
        self.current_scan_result = result
        self.results_page.set_result(result)
        self._prepare_result_comparison(result.scan_id)
        summary = f"扫描完成：{result.stats.scanned_files} 个文件，{len(result.findings)} 项风险"
        if not history_saved:
            summary += "；历史记录保存失败"
        self.statusBar().showMessage(summary)

    def _handle_scan_cancelled(self, result: ScanResult) -> None:
        try:
            self.runtime.database.save_scan_result(result)
        except Exception:
            self.statusBar().showMessage("扫描已取消，历史摘要保存失败")
        else:
            self.history_page.refresh()
            self._refresh_overview()

    def _open_history(self, scan_id: int) -> None:
        try:
            result = self.runtime.database.load_scan_result(scan_id)
        except KeyError:
            QMessageBox.warning(self, "无法打开", "这条扫描记录已经不存在。")
            return
        self.current_scan_result = result
        self.results_page.set_result(result)
        self._prepare_result_comparison(scan_id)
        self._show_results()

    def _prepare_result_comparison(self, scan_id: int | None) -> None:
        previous = self.runtime.database.previous_completed_scan(scan_id) if scan_id else None
        self.current_comparison_scan_id = scan_id if previous else None
        self.results_page.set_comparison_available(
            previous is not None,
            "与同一项目上一次已完成扫描比较" if previous else "这是该项目首次完成扫描",
        )

    def _show_current_comparison(self) -> None:
        if self.current_comparison_scan_id is not None:
            self._show_comparison(self.current_comparison_scan_id)

    def _show_comparison(self, scan_id: int) -> None:
        previous_record = self.runtime.database.previous_completed_scan(scan_id)
        records = {item.scan_id: item for item in self.runtime.database.list_scan_history()}
        current_record = records.get(scan_id)
        if current_record is None:
            return
        if previous_record is None:
            self.comparison_page.set_no_baseline(current_record.project_name)
        else:
            current = self.runtime.database.load_scan_result(scan_id)
            previous = self.runtime.database.load_scan_result(previous_record.scan_id)
            comparison = compare_scans(
                previous_record.scan_id,
                previous.findings,
                scan_id,
                current.findings,
            )
            self.comparison_page.set_comparison(current_record, previous_record, comparison)
        self.navigation.setCurrentRow(-1)
        self._set_stack_page(self.comparison_page)

    def _open_comparison_finding(self, finding: Finding) -> None:
        if finding.scan_id is None:
            return
        result = self.runtime.database.load_scan_result(finding.scan_id)
        self.current_scan_result = result
        self.results_page.set_result(result)
        self._prepare_result_comparison(finding.scan_id)
        self._show_results()
        for row, item in enumerate(self.results_page.filtered_findings):
            if item.fingerprint == finding.fingerprint:
                self.results_page.table.selectRow(row)
                break

    def _change_finding_status(self, finding, status: str) -> None:
        if finding.database_id is None:
            return
        try:
            self.runtime.database.update_finding_status(finding.database_id, status)
        except (KeyError, ValueError):
            QMessageBox.warning(self, "无法保存状态", "风险状态保存失败。")
            return
        self.results_page.update_finding_status(finding.database_id, status)

    def _add_finding_to_whitelist(self, finding) -> None:
        if not finding.fingerprint:
            return
        try:
            self.runtime.database.add_whitelist(
                "fingerprint", finding.fingerprint, f"{finding.rule_name or finding.rule_id} · {finding.relative_path}"
            )
        except ValueError:
            QMessageBox.warning(self, "无法加入白名单", "该风险项无法加入白名单。")
            return
        self.whitelist_page.refresh()
        QMessageBox.information(self, "已加入白名单", "下次扫描将不再提示相同风险。")

    def _refresh_overview(self) -> None:
        counts = self.runtime.database.dashboard_counts()
        for key, label in self.overview_values.items():
            label.setText(str(counts[key]))
        severity = self.runtime.database.dashboard_severity_counts()
        maximum = max(severity.values(), default=0) or 1
        for key, (bar, value) in self.severity_bars.items():
            bar.setRange(0, maximum)
            bar.setValue(severity[key])
            value.setText(str(severity[key]))
        recent = self.runtime.database.recent_completed_scans(5)
        self.recent_table.setRowCount(len(recent))
        for row, record in enumerate(recent):
            moment = record.finished_at or record.started_at
            values = (record.project_name, str(record.finding_count), moment.strftime("%m-%d %H:%M"))
            for column, text in enumerate(values):
                item = QTableWidgetItem(text)
                if column == 0:
                    item.setToolTip(record.project_name)
                else:
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.recent_table.setItem(row, column, item)
        records = self.runtime.database.list_scan_history()
        totals = {
            "candidates": sum(item.candidate_files for item in records),
            "skipped": sum(item.skipped_files for item in records),
            "errors": sum(item.read_errors for item in records),
            "suppressed": sum(item.suppressed_findings for item in records),
            "rules": sum(1 for item in self.runtime.database.list_managed_rules() if item.enabled),
            "whitelist": sum(1 for item in self.runtime.database.list_whitelist() if item.enabled),
        }
        for key, label in self.operational_values.items():
            label.setText(str(totals[key]))
        latest = self.runtime.database.latest_scan()
        if latest is None:
            self.recent_message.setText("还没有扫描记录。完成首次项目扫描后，这里会显示最近一次扫描。")
            self.recent_detail.setText("暂无记录")
            self.language_context.setText("暂无语言统计")
            self.language_table.setRowCount(0)
            return
        moment = latest.finished_at or latest.started_at
        self.recent_message.setText(
            f"{latest.project_name}　　{moment:%Y-%m-%d %H:%M:%S}"
        )
        self.recent_detail.setText(
            f"扫描文件 {latest.scanned_files}　风险 {latest.finding_count}　"
            f"严重 {latest.critical_count}　高 {latest.high_count}　耗时 {latest.duration_ms / 1000:.2f} 秒"
        )
        try:
            latest_result = self.runtime.database.load_scan_result(latest.scan_id)
        except KeyError:
            language_files = {}
        else:
            language_files = latest_result.stats.language_files
        total_language_files = sum(language_files.values())
        language_rows = sorted(language_files.items(), key=lambda item: (-item[1], item[0]))
        self.language_context.setText(f"{latest.project_name} · {len(language_rows)} 种语言")
        self.language_table.setRowCount(len(language_rows))
        for row, (language, count) in enumerate(language_rows):
            share = count / total_language_files * 100 if total_language_files else 0
            values = (language, str(count), f"{share:.1f}%")
            for column, text in enumerate(values):
                item = QTableWidgetItem(text)
                if column:
                    item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                self.language_table.setItem(row, column, item)

    def _load_latest_scan_path(self) -> None:
        latest = self.runtime.database.latest_scan()
        if latest is None:
            QMessageBox.information(self, "暂无扫描记录", "请先完成一次项目扫描，再使用重新扫描功能。")
            return
        project_root = Path(latest.project_root)
        if not project_root.exists() or not project_root.is_dir():
            QMessageBox.warning(self, "项目目录不可用", "最近扫描的项目目录已移动、删除或当前无法访问。")
            return
        self.scan_page.set_project_path(project_root)
        self.navigation.setCurrentRow(1)
        self.statusBar().showMessage(f"已载入项目：{project_root}")

    def _open_latest_result(self) -> None:
        latest = self.runtime.database.latest_scan()
        if latest is None:
            QMessageBox.information(self, "暂无扫描记录", "请先完成一次项目扫描，再查看最近结果。")
            return
        if latest.status not in {"completed", "cancelled"}:
            QMessageBox.information(self, "暂无可用结果", "最近一次扫描尚未产生可查看的结果。")
            return
        self._open_history(latest.scan_id)

    def _show_results(self) -> None:
        self.navigation.setCurrentRow(2)

    def closeEvent(self, event: QCloseEvent) -> None:
        if self.scan_page.shutdown():
            event.accept()
        else:
            self.statusBar().showMessage("正在取消扫描，请稍后再次关闭")
            event.ignore()

    def _apply_palette(self) -> None:
        palette = self.palette()
        palette.setColor(QPalette.ColorRole.Window, QColor("#F4F5F7"))
        palette.setColor(QPalette.ColorRole.WindowText, QColor("#17202A"))
        self.setPalette(palette)

    def _apply_panel_shadows(self) -> None:
        """Add restrained elevation to major surfaces, not every control."""
        elevated = {"summaryStrip"}
        for frame in self.findChildren(QFrame):
            if frame.objectName() not in elevated:
                continue
            effect = QGraphicsDropShadowEffect(frame)
            effect.setBlurRadius(10)
            effect.setOffset(0, 2)
            effect.setColor(QColor(20, 33, 44, 22))
            frame.setGraphicsEffect(effect)

    def _polish_data_views(self) -> None:
        """Give every result grid the same compact desktop-tool behavior."""
        for table in self.findChildren(QTableWidget):
            table.setAlternatingRowColors(True)
            table.setShowGrid(False)
            table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            table.verticalHeader().setDefaultSectionSize(34)
            table.horizontalHeader().setDefaultAlignment(
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
            )
            table.horizontalHeader().setHighlightSections(False)
