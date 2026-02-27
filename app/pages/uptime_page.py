"""
app/pages/uptime_page.py

The UI for System Tracker.
Optimized: Caches boot time to avoid repeated OS calls.
"""

from PyQt5 import QtWidgets, QtCore
from app.pages.base_page import BasePage, SummaryCard
import time
import psutil

class UptimePage(BasePage):
    def __init__(self, signals: QtCore.pyqtSignal):
        super().__init__("System Tracker")
        self.signals = signals
        
        # --- Cards ---
        card_layout = QtWidgets.QHBoxLayout()
        self.card_iface = SummaryCard("Interface", "eth0")
        self.card_status = SummaryCard("Status", "Connected")
        self.card_start = SummaryCard("System Boot", "N/A")
        self.card_uptime = SummaryCard("System Uptime", "0s")
        
        card_layout.addWidget(self.card_iface)
        card_layout.addWidget(self.card_status)
        card_layout.addWidget(self.card_start)
        card_layout.addWidget(self.card_uptime)
        self.get_layout().addLayout(card_layout)
        
        self.get_layout().addStretch()

        # OPTIMIZATION: Cache boot time once on init to avoid repeated I/O calls
        try:
            self.boot_time = psutil.boot_time()
            self.card_start.set_value(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.boot_time)))
        except Exception:
            self.boot_time = None
            self.card_start.set_value("Unknown")

    def update_uptime(self, _=None):
        """
        Called by MainWindow global timer.
        Uses cached boot timestamp for O(1) calculation efficiency.
        """
        if self.boot_time:
            uptime_s = int(time.time() - self.boot_time)
            
            m, s = divmod(uptime_s, 60)
            h, m = divmod(m, 60)
            d, h = divmod(h, 24)
            
            self.card_uptime.set_value(f"{d}d {h}h {m}m {s}s")
        else:
            self.card_uptime.set_value("Error")
        
    def set_connection_info(self, iface: str, status: str):
        """Public slot to update connection details."""
        self.card_iface.set_value(iface)
        self.card_status.set_value(status)
