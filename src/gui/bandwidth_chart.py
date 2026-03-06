"""
Live scrolling bandwidth / packet-rate chart for NetGuard.

Implemented purely with QPainter – no matplotlib or other extra
dependencies required.
"""

from __future__ import annotations

from collections import deque

from PyQt5.QtCore import Qt, QRect, QPoint
from PyQt5.QtGui import (
    QPainter, QPen, QColor, QBrush, QFont, QLinearGradient, QPainterPath,
)
from PyQt5.QtWidgets import QWidget

from src.gui.theme import ACCENT, BG_DARKEST, BG_PANEL, BORDER, TEXT_DIM


# How many 1-second buckets to keep on screen
_HISTORY = 60


class BandwidthChart(QWidget):
    """
    Dual-line scrolling chart showing:
      - bytes/second  (blue line, left y-axis)
      - packets/second (orange line, right y-axis)

    Call :meth:`push_sample` once per second with the current values.
    """

    _BLUE   = "#4fc3f7"
    _ORANGE = "#FF8800"
    _PAD_L  = 58   # pixels left of chart area (y-axis labels)
    _PAD_R  = 58   # pixels right of chart area
    _PAD_T  = 14
    _PAD_B  = 26   # x-axis labels

    def __init__(self, parent=None):
        super().__init__(parent)
        self._bps: deque[float] = deque([0.0] * _HISTORY, maxlen=_HISTORY)
        self._pps: deque[float] = deque([0.0] * _HISTORY, maxlen=_HISTORY)
        self.setMinimumHeight(130)
        self.setAttribute(Qt.WA_OpaquePaintEvent)

    # ── Public API ──────────────────────────────────────────────────────────

    def push_sample(self, bytes_per_sec: float, pkts_per_sec: float) -> None:
        """Append a new data point and repaint."""
        self._bps.append(max(0.0, bytes_per_sec))
        self._pps.append(max(0.0, pkts_per_sec))
        self.update()

    def reset(self) -> None:
        self._bps = deque([0.0] * _HISTORY, maxlen=_HISTORY)
        self._pps = deque([0.0] * _HISTORY, maxlen=_HISTORY)
        self.update()

    # ── Painting ────────────────────────────────────────────────────────────

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)

        w = self.width()
        h = self.height()

        # Background
        p.fillRect(0, 0, w, h, QColor(BG_DARKEST))

        chart_x = self._PAD_L
        chart_y = self._PAD_T
        chart_w = w - self._PAD_L - self._PAD_R
        chart_h = h - self._PAD_T - self._PAD_B

        if chart_w < 10 or chart_h < 10:
            return

        # Grid lines
        grid_pen = QPen(QColor(BORDER))
        grid_pen.setWidth(1)
        p.setPen(grid_pen)
        for i in range(5):
            y = chart_y + chart_h * i // 4
            p.drawLine(chart_x, y, chart_x + chart_w, y)

        # Draw the two data series
        self._draw_series(p, chart_x, chart_y, chart_w, chart_h,
                          self._bps, self._BLUE, fill=True)
        self._draw_series(p, chart_x, chart_y, chart_w, chart_h,
                          self._pps, self._ORANGE, fill=False, right_axis=True)

        # Y-axis labels (left = bytes/s, right = pkts/s)
        self._draw_y_labels(p, chart_x, chart_y, chart_h, self._bps,
                            self._BLUE, right=False, unit_fn=_fmt_bytes)
        self._draw_y_labels(p, chart_x + chart_w, chart_y, chart_h, self._pps,
                            self._ORANGE, right=True, unit_fn=lambda v: f"{int(v)}")

        # X-axis labels
        p.setPen(QColor(TEXT_DIM))
        small_font = QFont()
        small_font.setPointSize(8)
        p.setFont(small_font)
        p.drawText(QRect(chart_x, h - self._PAD_B, 30, self._PAD_B),
                   Qt.AlignLeft | Qt.AlignVCenter, f"-{_HISTORY}s")
        p.drawText(QRect(chart_x + chart_w - 20, h - self._PAD_B, 24, self._PAD_B),
                   Qt.AlignRight | Qt.AlignVCenter, "now")

        # Legend
        self._draw_legend(p, chart_x, chart_y)

        # Border
        p.setPen(QPen(QColor(BORDER), 1))
        p.drawRect(chart_x, chart_y, chart_w, chart_h)

    def _draw_series(
        self, p: QPainter,
        cx: int, cy: int, cw: int, ch: int,
        data: deque[float],
        color: str,
        fill: bool,
        right_axis: bool = False,
    ) -> None:
        samples = list(data)
        n = len(samples)
        if n < 2:
            return

        max_val = max(samples) or 1.0
        step_x = cw / (n - 1)

        def to_xy(i: int, v: float):
            x = cx + i * step_x
            y = cy + ch - (v / max_val) * ch
            return x, y

        path = QPainterPath()
        x0, y0 = to_xy(0, samples[0])
        path.moveTo(x0, y0)
        for i in range(1, n):
            x, y = to_xy(i, samples[i])
            path.lineTo(x, y)

        # Filled area below the line
        if fill:
            fill_path = QPainterPath(path)
            fill_path.lineTo(cx + cw, cy + ch)
            fill_path.lineTo(cx, cy + ch)
            fill_path.closeSubpath()
            grad = QLinearGradient(0, cy, 0, cy + ch)
            c = QColor(color)
            c.setAlpha(80)
            grad.setColorAt(0.0, c)
            c2 = QColor(color)
            c2.setAlpha(0)
            grad.setColorAt(1.0, c2)
            p.fillPath(fill_path, QBrush(grad))

        pen = QPen(QColor(color), 2)
        p.setPen(pen)
        p.drawPath(path)

        # Dot at latest value
        lx, ly = to_xy(n - 1, samples[-1])
        p.setBrush(QBrush(QColor(color)))
        p.setPen(Qt.NoPen)
        p.drawEllipse(QPoint(int(lx), int(ly)), 4, 4)

    def _draw_y_labels(
        self,
        p: QPainter,
        axis_x: int, cy: int, ch: int,
        data: deque[float],
        color: str,
        right: bool,
        unit_fn,
    ) -> None:
        max_val = max(data) or 1.0
        small = QFont()
        small.setPointSize(8)
        p.setFont(small)
        p.setPen(QColor(color))

        for frac in (1.0, 0.5, 0.0):
            val = max_val * frac
            y = int(cy + ch * (1.0 - frac))
            label = unit_fn(val)
            rect_w = self._PAD_L - 4
            if right:
                rect = QRect(axis_x + 4, y - 8, rect_w, 16)
                align = Qt.AlignLeft | Qt.AlignVCenter
            else:
                rect = QRect(axis_x - rect_w - 2, y - 8, rect_w, 16)
                align = Qt.AlignRight | Qt.AlignVCenter
            p.drawText(rect, align, label)

    def _draw_legend(self, p: QPainter, cx: int, cy: int) -> None:
        small = QFont()
        small.setPointSize(8)
        p.setFont(small)
        x = cx + 6
        y = cy + 4

        for color, label in ((self._BLUE, "Bandwidth"), (self._ORANGE, "Pkt/s")):
            p.fillRect(x, y + 4, 14, 3, QColor(color))
            p.setPen(QColor(color))
            p.drawText(x + 18, y, 70, 14, Qt.AlignLeft | Qt.AlignVCenter, label)
            x += 90


def _fmt_bytes(v: float) -> str:
    for unit in ("B/s", "KB/s", "MB/s", "GB/s"):
        if v < 1024:
            return f"{v:.0f}{unit}"
        v /= 1024
    return f"{v:.0f}TB/s"
