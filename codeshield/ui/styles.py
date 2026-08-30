APP_STYLE = """
QMainWindow, QWidget {
    background: #F4F6F8;
    color: #1D2939;
    font-family: "Microsoft YaHei UI";
    font-size: 14px;
}
QLabel, QCheckBox { background: transparent; }

#sidebar { background: #FFFFFF; border-right: 1px solid #E4E7EC; }
#brand { color: #1D2939; font-size: 18px; font-weight: 700; }
#brandSubtitle, #phaseLabel { color: #98A2B3; font-size: 11px; }
#navigation { border: 0; outline: 0; background: transparent; }
#navigation::item {
    border-radius: 6px;
    padding: 10px 11px;
    margin: 1px 2px;
    color: #475467;
}
#navigation::item:hover { background: #F2F4F7; color: #344054; }
#navigation::item:selected { background: #EEF4FF; color: #175CD3; font-weight: 600; }

#pageTitle { color: #101828; font-size: 24px; font-weight: 700; }
#pageSubtitle { color: #667085; font-size: 13px; margin-bottom: 2px; }

#statCard, #contentCard, #surfacePanel, #toolbarPanel {
    background: #FFFFFF;
    border: 1px solid #E4E7EC;
    border-radius: 7px;
}
#statCard { border-color: #E8ECF2; }
#contentCard, #surfacePanel { padding: 18px; }
#toolbarPanel { padding: 12px; }
#sectionDivider { background: #EAECF0; border: 0; }
#statNumber { color: #101828; font-size: 25px; font-weight: 700; }
#statCaption { color: #667085; font-size: 12px; }
#cardTitle { color: #101828; font-size: 16px; font-weight: 600; }
#mutedText { color: #667085; }
#recentPrimary { color: #344054; font-size: 14px; font-weight: 600; }
#emptyText { color: #98A2B3; font-size: 13px; }
#smallStatValue { color: #101828; font-size: 18px; font-weight: 700; }
#noticeText {
    color: #475467;
    background: #F8FAFC;
    border: 1px solid #EAECF0;
    border-radius: 6px;
    padding: 9px;
}
#detailSection { color: #344054; font-weight: 600; margin-top: 5px; }
#maskedValue {
    color: #344054;
    background: #F8FAFC;
    border: 1px solid #EAECF0;
    border-radius: 5px;
    padding: 8px;
    font-family: Consolas, "Microsoft YaHei UI";
}

QLineEdit, QComboBox, QSpinBox, QPlainTextEdit {
    background: #FFFFFF;
    border: 1px solid #D0D5DD;
    border-radius: 5px;
    padding: 7px 9px;
    selection-background-color: #D1E0FF;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus { border-color: #84ADFF; }
QComboBox::drop-down { border: 0; width: 22px; }

QPushButton {
    min-height: 21px;
    border: 1px solid #D0D5DD;
    border-radius: 5px;
    padding: 8px 14px;
    background: #FFFFFF;
    color: #344054;
    font-weight: 600;
}
QPushButton:hover { background: #F9FAFB; border-color: #98A2B3; }
QPushButton:pressed { background: #F2F4F7; }
QPushButton:disabled { color: #98A2B3; background: #F2F4F7; border-color: #EAECF0; }
#primaryButton { color: #FFFFFF; background: #175CD3; border-color: #175CD3; }
#primaryButton:hover { background: #1849A9; border-color: #1849A9; }
#secondaryButton { color: #344054; background: #FFFFFF; border-color: #D0D5DD; }
#dangerButton { color: #B42318; background: #FFFFFF; border-color: #FDA29B; }
#dangerButton:hover { color: #912018; background: #FFF5F4; border-color: #F97066; }

QProgressBar {
    min-height: 13px;
    border: 0;
    border-radius: 4px;
    background: #EAECF0;
    text-align: center;
    color: #344054;
}
QProgressBar::chunk { border-radius: 4px; background: #2E6FD8; }

QTableWidget {
    background: #FFFFFF;
    alternate-background-color: #F9FAFB;
    border: 1px solid #E4E7EC;
    border-radius: 5px;
    gridline-color: #EAECF0;
    selection-background-color: #EEF4FF;
    selection-color: #101828;
}
QTableWidget::item { min-height: 24px; padding: 6px 7px; }
QTableWidget::item:selected { background: #E7F0FF; color: #101828; }
QHeaderView::section {
    background: #F9FAFB;
    border: 0;
    border-bottom: 1px solid #E4E7EC;
    padding: 8px;
    font-weight: 600;
    color: #475467;
}
#codeContext { font-family: Consolas, "Microsoft YaHei UI"; background: #182230; color: #F2F4F7; }
QScrollBar:vertical { width: 10px; margin: 2px; background: transparent; }
QScrollBar::handle:vertical { min-height: 28px; border-radius: 4px; background: #C9D2E0; }
QScrollBar::handle:vertical:hover { background: #AEB9CA; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { height: 10px; background: transparent; }
QScrollBar::handle:horizontal { min-width: 28px; border-radius: 4px; background: #C9D2E0; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QStatusBar { background: #FFFFFF; color: #667085; border-top: 1px solid #E4E7EC; }
"""
