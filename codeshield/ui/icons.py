"""窗口品牌图标与界面线性图标。"""
from __future__ import annotations

import math
import sys
from pathlib import Path

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap

PROJECT_DIR = Path(__file__).resolve().parent.parent.parent
APP_ICON_PATH = PROJECT_DIR / "1.png"


def configure_windows_app_id() -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes

        # Windows 按此标识生成任务栏分组，否则会沿用 python.exe 图标。
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "CodeShield.Desktop.Scanner"
        )
    except (AttributeError, OSError):
        pass


def app_icon() -> QIcon:
    icon = QIcon()
    if APP_ICON_PATH.exists():
        icon.addFile(str(APP_ICON_PATH))
    return icon


def app_icon_pixmap(size: int) -> QPixmap:
    pix = QPixmap(str(APP_ICON_PATH)) if APP_ICON_PATH.exists() else QPixmap(size, size)
    if pix.isNull():
        return QPixmap(size, size)
    return pix.scaled(size, size, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)


def _pen(p: QPainter, color: str, width: float = 1.8) -> None:
    pen = QPen(QColor(color))
    pen.setWidthF(width)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)


def _d_overview(p: QPainter) -> None:
    p.drawLine(3, 11, 12, 4)
    p.drawLine(12, 4, 21, 11)
    p.drawLine(4.5, 10, 4.5, 20)
    p.drawLine(19.5, 10, 19.5, 20)
    p.drawLine(4.5, 20, 19.5, 20)
    p.drawLine(10, 20, 10, 15)
    p.drawLine(14, 20, 14, 15)
    p.drawLine(10, 15, 14, 15)


def _d_scan(p: QPainter) -> None:
    p.drawEllipse(QRectF(4, 4, 11, 11))
    p.drawLine(13, 13, 20, 20)


def _d_results(p: QPainter) -> None:
    p.drawRoundedRect(QRectF(3, 4, 18, 16), 2, 2)
    p.drawLine(3, 9, 21, 9)
    p.drawLine(3, 14, 21, 14)
    p.drawLine(12, 4, 12, 20)


def _d_history(p: QPainter) -> None:
    p.drawEllipse(QRectF(3, 3, 18, 18))
    p.drawLine(12, 7, 12, 12)
    p.drawLine(12, 12, 16, 15)


def _d_rules(p: QPainter) -> None:
    path = QPainterPath()
    path.moveTo(12, 2.5)
    path.lineTo(20.5, 5)
    path.lineTo(20.5, 12)
    path.quadTo(20.5, 17.5, 12, 21.5)
    path.quadTo(3.5, 17.5, 3.5, 12)
    path.lineTo(3.5, 5)
    path.closeSubpath()
    p.drawPath(path)
    p.drawLine(8.5, 12, 11, 14.5)
    p.drawLine(11, 14.5, 15.5, 9.5)


def _d_whitelist(p: QPainter) -> None:
    p.drawRoundedRect(QRectF(4, 3, 16, 18), 2, 2)
    p.drawLine(8, 11.5, 11, 14.5)
    p.drawLine(11, 14.5, 16, 9)


def _d_reports(p: QPainter) -> None:
    path = QPainterPath()
    path.moveTo(6, 3)
    path.lineTo(14, 3)
    path.lineTo(19, 8)
    path.lineTo(19, 21)
    path.lineTo(6, 21)
    path.closeSubpath()
    p.drawPath(path)
    p.drawLine(14, 3, 14, 8)
    p.drawLine(14, 8, 19, 8)
    p.drawLine(9, 16, 11.5, 13.5)
    p.drawLine(11.5, 13.5, 13.5, 15.5)
    p.drawLine(13.5, 15.5, 16, 13.5)


def _d_settings(p: QPainter) -> None:
    p.drawEllipse(QRectF(7, 7, 10, 10))
    for i in range(8):
        angle = math.pi / 4 * i
        x1 = 12 + math.cos(angle) * 7
        y1 = 12 + math.sin(angle) * 7
        x2 = 12 + math.cos(angle) * 10.2
        y2 = 12 + math.sin(angle) * 10.2
        p.drawLine(x1, y1, x2, y2)


def _d_folder(p: QPainter) -> None:
    path = QPainterPath()
    path.moveTo(3.5, 7)
    path.lineTo(9.5, 7)
    path.lineTo(11.5, 10)
    path.lineTo(20.5, 10)
    path.lineTo(20.5, 18)
    path.lineTo(3.5, 18)
    path.closeSubpath()
    p.drawPath(path)


def _d_file(p: QPainter) -> None:
    path = QPainterPath()
    path.moveTo(6, 3)
    path.lineTo(14, 3)
    path.lineTo(19, 8)
    path.lineTo(19, 21)
    path.lineTo(6, 21)
    path.closeSubpath()
    p.drawPath(path)
    p.drawLine(14, 3, 14, 8)
    p.drawLine(14, 8, 19, 8)


def _d_risk(p: QPainter) -> None:
    path = QPainterPath()
    path.moveTo(12, 3.5)
    path.lineTo(21.5, 19.5)
    path.lineTo(2.5, 19.5)
    path.closeSubpath()
    p.drawPath(path)
    p.drawLine(12, 9.5, 12, 14.5)
    p.drawLine(12, 16.5, 12, 17.5)


def _d_critical(p: QPainter) -> None:
    path = QPainterPath()
    path.moveTo(13.5, 2.5)
    path.lineTo(6.5, 12.5)
    path.lineTo(11, 12.5)
    path.lineTo(10.5, 21.5)
    path.lineTo(17.5, 11.5)
    path.lineTo(13, 11.5)
    path.closeSubpath()
    p.drawPath(path)


_DRAWERS = {
    "overview": _d_overview,
    "scan": _d_scan,
    "results": _d_results,
    "history": _d_history,
    "rules": _d_rules,
    "whitelist": _d_whitelist,
    "reports": _d_reports,
    "settings": _d_settings,
    "folder": _d_folder,
    "file": _d_file,
    "risk": _d_risk,
    "critical": _d_critical,
}


def icon_pixmap(kind: str, color: str = "#6B7A90", size: int = 24) -> QPixmap:
    pix = QPixmap(size, size)
    pix.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pix)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.scale(size / 24.0, size / 24.0)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    _pen(painter, color)
    drawer = _DRAWERS.get(kind)
    if drawer is not None:
        drawer(painter)
    painter.end()
    return pix


def empty_state_pixmap(width: int = 180, height: int = 130, color: str = "#AEC6F0") -> QPixmap:
    """概览页“最近扫描”空状态插画：剪贴板清单 + 放大镜。"""
    pix = QPixmap(width, height)
    pix.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pix)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    _pen(painter, color, 3.2)
    w, h = float(width), float(height)
    cw, ch = w * 0.42, h * 0.56
    cx, cy = w * 0.30, h * 0.20
    painter.drawRoundedRect(QRectF(cx, cy, cw, ch), 8, 8)
    painter.drawLine(cx + cw * 0.28, cy, cx + cw * 0.28, cy - h * 0.06)
    painter.drawLine(cx + cw * 0.72, cy, cx + cw * 0.72, cy - h * 0.06)
    painter.drawLine(cx + cw * 0.2, cy + ch * 0.32, cx + cw * 0.8, cy + ch * 0.32)
    painter.drawLine(cx + cw * 0.2, cy + ch * 0.55, cx + cw * 0.8, cy + ch * 0.55)
    lx, ly, lr = w * 0.56, h * 0.48, h * 0.30
    painter.drawEllipse(QRectF(lx, ly, lr, lr))
    painter.drawLine(lx + lr * 0.82, ly + lr * 0.82, lx + lr * 1.35, ly + lr * 1.35)
    painter.end()
    return pix
