"""
app/pages/firewall_page.py

UI for the Firewall & WAF Detector.
Part of the 'Web Play' suite.
FIXED: Shows 'Firewall Presence' (Yes/No) with color coding.
"""

from PyQt5 import QtWidgets, QtCore
from PyQt5.QtCore import pyqtSignal
from app.pages.base_page import BasePage, SummaryCard

class FirewallPage(BasePage):
    start_scan = pyqtSignal(str) # Signal to main window to start worker

    def __init__(self, signals: QtCore.pyqtSignal):
        super().__init__("Firewall & WAF Detection")
        self.signals = signals
        
        # --- Controls ---
        ctrl_layout = QtWidgets.QHBoxLayout()
        ctrl_layout.addWidget(QtWidgets.QLabel("Target URL/IP:"))
        self.target_input = QtWidgets.QLineEdit()
        self.target_input.setPlaceholderText("e.g., example.com or 192.168.1.50")
        ctrl_layout.addWidget(self.target_input)
        
        self.scan_btn = QtWidgets.QPushButton("Detect Firewall")
        ctrl_layout.addWidget(self.scan_btn)
        ctrl_layout.addStretch()
        self.get_layout().addLayout(ctrl_layout)
        
        # --- Results Cards ---
        card_layout = QtWidgets.QHBoxLayout()
        self.card_status = SummaryCard("Connection Status", "Idle")
        
        # Renamed from "Firewall Type" to "Firewall Presence" for clarity
        self.card_presence = SummaryCard("Firewall Presence", "---")
        
        self.card_waf = SummaryCard("WAF Vendor", "---")
        
        card_layout.addWidget(self.card_status)
        card_layout.addWidget(self.card_presence)
        card_layout.addWidget(self.card_waf)
        self.get_layout().addLayout(card_layout)
        
        # --- Log Output ---
        self.log_box = QtWidgets.QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setPlaceholderText("Detection logs will appear here...")
        self.get_layout().addWidget(self.log_box)
        
        self.scan_btn.clicked.connect(self._start)

    def _start(self):
        target = self.target_input.text()
        if not target:
            self.signals.log.emit("error", "Please enter a target.")
            return
            
        self.scan_btn.setEnabled(False)
        self.log_box.clear()
        self.card_status.set_value("Scanning...")
        self.card_presence.set_value("Analyzing...")
        # Reset style
        self.card_presence.value_label.setStyleSheet("color: #e6fff4; font-weight: bold;") 
        self.card_waf.set_value("---")
        
        # Emit signal to main window to spawn worker
        self.start_scan.emit(target)

    def append_log(self, msg):
        self.log_box.append(msg)
        
    def show_result(self, report):
        self.scan_btn.setEnabled(True)
        
        self.card_status.set_value(report.get("status", "Unknown"))
        
        # Display Yes/No for presence
        presence = report.get("presence", "Unknown")
        self.card_presence.set_value(presence)
        
        # Color code Yes/No for better visibility
        # Orange/Red if a firewall IS detected (Warning/Alert style)
        # Green if NO firewall is detected (Open/Direct access)
        if "Yes" in presence:
            self.card_presence.value_label.setStyleSheet("color: #ff4500; font-weight: bold; font-size: 14pt;") # Orange Red
        else:
            self.card_presence.value_label.setStyleSheet("color: #00ff99; font-weight: bold; font-size: 14pt;") # Green
            
        self.card_waf.set_value(report.get("waf", "None"))
        
        self.signals.log.emit('success', f"Firewall scan finished for {report.get('target')}")
