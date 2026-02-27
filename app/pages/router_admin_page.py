"""
app/pages/router_admin_page.py

The UI for Router Admin Access.
"""

from PyQt5 import QtWidgets, QtCore
from app.pages.base_page import BasePage, SummaryCard
import webbrowser

class RouterAdminPage(BasePage):
    def __init__(self, signals: QtCore.pyqtSignal):
        super().__init__("Router Admin Access")
        self.signals = signals
        
        # --- Info Cards ---
        card_layout = QtWidgets.QHBoxLayout()
        self.card_gw = SummaryCard("Gateway IP", "N/A")
        self.card_model = SummaryCard("Router Model", "Unknown")
        card_layout.addWidget(self.card_gw)
        card_layout.addWidget(self.card_model)
        self.get_layout().addLayout(card_layout)

        # --- Action Button ---
        info_layout = QtWidgets.QVBoxLayout()
        self.open_btn = QtWidgets.QPushButton("Open Admin Page in Browser")
        self.open_btn.setMinimumHeight(40)
        info_layout.addWidget(self.open_btn)
        info_layout.addStretch()
        self.get_layout().addLayout(info_layout)
        
        self.open_btn.clicked.connect(self._open_gateway)
        
    def _open_gateway(self):
        gateway_ip = self.card_gw.value_label.text()
        if gateway_ip == 'N/A':
            self.signals.log.emit('error', "Gateway IP not found.")
            return
            
        url = f'http://{gateway_ip}'
        self.signals.log.emit('info', f"Opening {url} in browser...")
        try:
            webbrowser.open(url)
        except Exception as e:
            self.signals.log.emit('error', f"Failed to open browser: {e}")
        
    def set_info(self, ip: str, model: str):
        """Public slot to update router info."""
        self.card_gw.set_value(ip)
        self.card_model.set_value(model)
