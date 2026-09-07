PRIMARY = "#0F6CBD"
CRITICAL = "#C42B1C"
HIGH = "#D97706"
MEDIUM = "#CA8A04"
LOW = "#2878C8"
BACKGROUND = "#F4F5F7"
SURFACE = "#FFFFFF"
TEXT = "#17202A"
MUTED = "#68717A"
BORDER = "#D6DADE"
DISABLED = "#A6ADB4"
SUCCESS = "#16835D"

APP_STYLE = """
QMainWindow, QWidget {
    background: #F4F5F7;
    color: #17202A;
    font-family: "Microsoft YaHei UI";
    font-size: 13px;
}
QLabel, QCheckBox { background: transparent; }

#applicationShell, #workspace, #pageSurface { background: #F4F5F7; }
#sidebar { background: #F0F2F4; border-right: 1px solid #D6DADE; }
#brand { color: #17202A; font-size: 18px; font-weight: 700; }
#brandSubtitle, #phaseLabel { color: #7B848D; font-size: 11px; }
#navigation { border: 0; outline: 0; background: transparent; }
#navigation::item {
    border: 1px solid transparent;
    border-radius: 4px;
    padding: 10px 11px;
    margin: 2px 1px;
    color: #4F5B66;
}
#navigation::item:hover { background: #E7EAED; color: #25313B; }
#navigation::item:selected {
    background: #E2EEF9;
    color: #0F5FA6;
    font-weight: 600;
    border-color: #D1E2F1;
    border-left: 3px solid #0F6CBD;
}

#pageTitle { color: #17202A; font-size: 22px; font-weight: 700; }
#pageSubtitle { color: #68717A; font-size: 13px; margin-bottom: 3px; }

#summaryStrip, #recentStrip, #contentCard, #surfacePanel, #toolbarPanel {
    background: #FFFFFF;
    border: 1px solid #D6DADE;
    border-radius: 4px;
}
#summaryStrip { border-top: 2px solid #7E96AA; }
#recentStrip { background: #FAFBFC; }
#summaryMetric { background: transparent; }
#metricDivider { background: #E1E4E7; border: 0; }
#metricIcon {
    background: #EDF3F8;
    border: 1px solid #D7E3EC;
    border-radius: 3px;
}
#contentCard, #surfacePanel { padding: 18px; }
#toolbarPanel { padding: 12px; background: #FAFBFC; }
#actionBar {
    background: #F0F2F4;
    border: 0;
    border-top: 1px solid #D6DADE;
    border-bottom: 1px solid #D6DADE;
    border-radius: 0;
}
#scanStatusCard {
    background: #FFFFFF;
    border: 1px solid #D6DADE;
    border-left: 3px solid #0F6CBD;
    border-radius: 4px;
    padding: 18px;
}
#sectionDivider { background: #E1E4E7; border: 0; }
#statNumber { color: #17202A; font-size: 24px; font-weight: 700; }
#statCaption { color: #68717A; font-size: 12px; }
#cardTitle { color: #202A33; font-size: 15px; font-weight: 700; }
#mutedText { color: #68717A; }
#recentPrimary { color: #26323C; font-size: 14px; font-weight: 600; }
#emptyText { color: #8A929A; font-size: 13px; }
#smallStatValue { color: #17202A; font-size: 18px; font-weight: 700; }
#operationalNumber { color: #263746; font-size: 19px; font-weight: 700; }
#noticeText {
    color: #29465B;
    background: #EEF6FC;
    border: 1px solid #CFE3F3;
    border-left: 3px solid #0F6CBD;
    border-radius: 4px;
    padding: 9px 11px;
}
#detailSection { color: #34414B; font-weight: 700; margin-top: 5px; }
#maskedValue {
    color: #26323C;
    background: #F6F7F8;
    border: 1px solid #D8DDE1;
    border-radius: 3px;
    padding: 8px;
    font-family: Consolas, "Microsoft YaHei UI";
}

QLineEdit, QComboBox, QSpinBox, QPlainTextEdit {
    background: #FFFFFF;
    border: 1px solid #B8C0C7;
    border-radius: 4px;
    padding: 7px 9px;
    selection-background-color: #CCE4F7;
    selection-color: #17202A;
}
#pathField { background: #F8F9FA; color: #36424C; }
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus {
    border: 1px solid #0F6CBD;
}
QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled, QPlainTextEdit:disabled {
    color: #8D949B;
    background: #ECEEEF;
    border-color: #D8DCDF;
}
QCheckBox { spacing: 7px; color: #34414B; }
QCheckBox:disabled { color: #8D949B; }
QComboBox::drop-down { border: 0; width: 22px; }

QPushButton {
    min-height: 22px;
    border: 1px solid #B8C0C7;
    border-radius: 4px;
    padding: 8px 14px;
    background: #FFFFFF;
    color: #26323C;
    font-weight: 500;
}
QPushButton:hover { background: #F1F3F5; border-color: #8F9AA3; }
QPushButton:pressed { background: #E6E9EC; }
QPushButton:focus { border-color: #0F6CBD; }
QPushButton:disabled {
    color: #979DA3;
    background: #ECEEEF;
    border-color: #D8DCDF;
}
#primaryButton { color: #FFFFFF; background: #0F6CBD; border-color: #0F6CBD; font-weight: 600; }
#primaryButton:hover { color: #FFFFFF; background: #0B5FA8; border-color: #0B5FA8; }
#primaryButton:pressed { background: #094F8C; }
#secondaryButton { color: #26323C; }
#dangerButton { color: #B42318; background: #FFFFFF; border-color: #D9A4A0; font-weight: 600; }
#dangerButton:hover { color: #9F1F15; background: #FFF4F3; border-color: #C77872; }
#primaryButton:disabled, #secondaryButton:disabled, #dangerButton:disabled {
    color: #979DA3;
    background: #ECEEEF;
    border-color: #D8DCDF;
}

QProgressBar {
    min-height: 12px;
    border: 0;
    border-radius: 3px;
    background: #E4E7EA;
    text-align: center;
    color: #34414B;
}
QProgressBar::chunk { border-radius: 3px; background: #2878C8; }

QTableWidget {
    background: #FFFFFF;
    alternate-background-color: #FAFBFC;
    border: 1px solid #D6DADE;
    border-radius: 4px;
    gridline-color: transparent;
    selection-background-color: #E2F0FA;
    selection-color: #17202A;
}
QTableWidget::item {
    min-height: 24px;
    padding: 6px 8px;
    border-bottom: 1px solid #ECEEF0;
}
QTableWidget::item:selected { background: #E2F0FA; color: #17202A; }
QHeaderView::section {
    background: #F3F5F6;
    border: 0;
    border-right: 1px solid #E1E4E7;
    border-bottom: 1px solid #D6DADE;
    padding: 8px;
    font-weight: 600;
    color: #46515B;
}
QTabWidget#managementTabs::pane {
    background: transparent;
    border: 0;
    border-top: 1px solid #D6DADE;
    top: -1px;
}
QTabBar::tab {
    background: transparent;
    color: #5F6972;
    border: 0;
    border-bottom: 2px solid transparent;
    padding: 9px 18px;
    margin-right: 6px;
    font-weight: 500;
}
QTabBar::tab:hover { color: #17202A; background: #ECEFF2; }
QTabBar::tab:selected { color: #0F5FA6; border-bottom-color: #0F6CBD; font-weight: 600; }
#codeContext {
    font-family: Consolas, "Microsoft YaHei UI";
    background: #1E252B;
    color: #E8ECEF;
    border-color: #151A1F;
}
QScrollBar:vertical { width: 10px; margin: 2px; background: transparent; }
QScrollBar::handle:vertical { min-height: 28px; border-radius: 4px; background: #C1C7CC; }
QScrollBar::handle:vertical:hover { background: #9EA6AD; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { height: 10px; background: transparent; }
QScrollBar::handle:horizontal { min-width: 28px; border-radius: 4px; background: #C1C7CC; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QStatusBar { background: #FFFFFF; color: #68717A; border-top: 1px solid #D6DADE; font-size: 12px; }
QToolTip { color: #FFFFFF; background: #30363D; border: 1px solid #20252A; padding: 5px 8px; }
QMessageBox { background: #F4F5F7; }
QMessageBox QLabel { color: #17202A; min-width: 260px; }
QSplitter::handle { background: #D8DDE1; width: 5px; }
"""
