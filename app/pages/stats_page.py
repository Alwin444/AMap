"""
app/pages/stats_page.py

The UI for the Network Statistics page.
Features:
- Real-time Traffic Pie Chart (Download vs Upload).
- Top Talkers Table (Active Connections).
- Refined Layout.
"""

from PyQt5 import QtWidgets, QtCore, QtGui
from app.pages.base_page import BasePage, SummaryCard

class TrafficPieChart(QtWidgets.QWidget):
    """
    A custom widget that draws a lightweight Pie Chart using QPainter.
    Visualizes Download vs Upload ratios.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(350) # Size Up: Bigger chart
        self.download_val = 0.0
        self.upload_val = 0.0

    def update_data(self, down_mb, up_mb):
        self.download_val = down_mb
        self.upload_val = up_mb
        self.update() # Trigger repaint

    def paintEvent(self, event):
        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.Antialiasing)
        
        # 1. Background
        rect = self.rect()
        painter.fillRect(rect, QtGui.QColor("#0a1525")) # Dark background
        
        # 2. Calculate Angles
        total = self.download_val + self.upload_val
        if total == 0:
            # Draw empty circle if no data
            painter.setPen(QtGui.QPen(QtGui.QColor("#333"), 2))
            painter.drawEllipse(rect.center(), 120, 120)
            self._draw_center_text(painter, rect, "No Data")
            return

        # 360 degrees * 16 (Qt uses 1/16th degree steps)
        angle_down = int((self.download_val / total) * 360 * 16)
        
        # 3. Draw Pie Slices
        # Define drawing area (centered square)
        size = min(rect.width(), rect.height()) - 40
        pie_rect = QtCore.QRectF((rect.width() - size)/2, (rect.height() - size)/2, size, size)
        
        start_angle = 90 * 16 # Start at top (12 o'clock)

        # Download Slice (Cyan)
        painter.setPen(QtCore.Qt.NoPen)
        painter.setBrush(QtGui.QColor("#00ffff"))
        painter.drawPie(pie_rect, start_angle, -angle_down) # Negative for clockwise
        
        # Upload Slice (Magenta)
        painter.setBrush(QtGui.QColor("#ff00ff"))
        # Fill the remainder to avoid rounding gaps
        painter.drawPie(pie_rect, start_angle - angle_down, -(360 * 16 - angle_down))

        # 4. Draw "Donut" Hole (Optional, looks modern)
        painter.setBrush(QtGui.QColor("#0a1525"))
        hole_size = size * 0.6 # Slightly larger hole
        hole_rect = QtCore.QRectF((rect.width() - hole_size)/2, (rect.height() - hole_size)/2, hole_size, hole_size)
        painter.drawEllipse(hole_rect)
        
        # 5. Center Text
        self._draw_center_text(painter, rect, f"Total\n{total:.1f} MB")

    def _draw_center_text(self, painter, rect, text):
        painter.setPen(QtGui.QColor("#e6f7ff"))
        font = painter.font()
        font.setBold(True)
        font.setPointSize(14)
        painter.setFont(font)
        painter.drawText(rect, QtCore.Qt.AlignCenter, text)

class StatsPage(BasePage):
    def __init__(self, signals: QtCore.pyqtSignal):
        super().__init__("Real-Time Network Statistics")
        self.signals = signals

        # Layout
        self.get_layout().setContentsMargins(20, 20, 20, 20)
        self.get_layout().setSpacing(20)

        # --- 1. Summary Cards ---
        card_layout = QtWidgets.QHBoxLayout()
        card_layout.setSpacing(15)
        
        self.card_in = SummaryCard("Download Speed", "0 Kbps")
        self.card_out = SummaryCard("Upload Speed", "0 Kbps")
        self.card_total = SummaryCard("Total Session Data", "0 MB")
        
        for card in [self.card_in, self.card_out, self.card_total]:
            card.setMinimumHeight(100) # Size Up
            card_layout.addWidget(card)
            
        self.get_layout().addLayout(card_layout)

        # --- 2. Main Content (Chart vs Table) ---
        main_layout = QtWidgets.QHBoxLayout()
        main_layout.setSpacing(20)
        
        # Left: Pie Chart Section
        graph_group = QtWidgets.QGroupBox("Traffic Distribution")
        graph_group.setStyleSheet("QGroupBox { font-weight: bold; font-size: 11pt; }")
        graph_layout = QtWidgets.QVBoxLayout()
        
        self.pie_chart = TrafficPieChart()
        graph_layout.addWidget(self.pie_chart)
        
        # Legend
        legend = QtWidgets.QHBoxLayout()
        legend.addStretch()
        lbl_down = QtWidgets.QLabel("■ Download"); lbl_down.setStyleSheet("color: #00ffff; font-weight: bold; font-size: 11pt;")
        lbl_up = QtWidgets.QLabel("■ Upload"); lbl_up.setStyleSheet("color: #ff00ff; font-weight: bold; font-size: 11pt;")
        legend.addWidget(lbl_down)
        legend.addSpacing(20)
        legend.addWidget(lbl_up)
        legend.addStretch()
        graph_layout.addLayout(legend)
        
        graph_group.setLayout(graph_layout)
        main_layout.addWidget(graph_group, 1) # Equal width
        
        # Right: Top Talkers Section
        talkers_group = QtWidgets.QGroupBox("Top Active Connections")
        talkers_group.setStyleSheet("QGroupBox { font-weight: bold; font-size: 11pt; }")
        talkers_layout = QtWidgets.QVBoxLayout()
        
        self.talkers_table = QtWidgets.QTableWidget(0, 2)
        self.talkers_table.setHorizontalHeaderLabels(["Remote IP", "Connections"])
        self.talkers_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.talkers_table.verticalHeader().setVisible(False)
        self.talkers_table.setAlternatingRowColors(True)
        # Remove grid for cleaner look
        self.talkers_table.setShowGrid(False)
        self.talkers_table.setStyleSheet("QTableWidget { border: none; background: rgba(0,0,0,0.2); }")
        
        talkers_layout.addWidget(self.talkers_table)
        talkers_group.setLayout(talkers_layout)
        main_layout.addWidget(talkers_group, 1) # Equal width
        
        self.get_layout().addLayout(main_layout)
        self.get_layout().addStretch()

    def update_stats(self, bw_in: float, bw_out: float, total_down: float, total_up: float, talkers: dict):
        """
        Called by the worker signal.
        Updates cards, pie chart, and top talkers table.
        """
        # 1. Update Cards
        self.card_in.set_value(f"{bw_in:.2f} Kbps")
        self.card_out.set_value(f"{bw_out:.2f} Kbps")
        
        total_mb = total_down + total_up
        self.card_total.set_value(f"{total_mb:.2f} MB")
        
        # 2. Update Pie Chart
        self.pie_chart.update_data(total_down, total_up)
        
        # 3. Update Talkers Table
        self.talkers_table.setRowCount(0)
        self.talkers_table.setSortingEnabled(False) # Disable sorting during rapid updates
        
        for ip, count in talkers.items():
            r = self.talkers_table.rowCount()
            self.talkers_table.insertRow(r)
            self.talkers_table.setItem(r, 0, QtWidgets.QTableWidgetItem(str(ip)))
            self.talkers_table.setItem(r, 1, QtWidgets.QTableWidgetItem(str(count)))
