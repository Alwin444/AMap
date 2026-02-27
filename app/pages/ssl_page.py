"""
app/pages/ssl_page.py

The UI for SSL Certificate Inspection.
FIXED: Added missing pyqtSignal import to prevent NameError.
"""

from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtCore import pyqtSignal # Crucial import
from app.pages.base_page import BasePage, SummaryCard

class SSLPage(BasePage):
    start_scan = pyqtSignal(str) 

    def __init__(self, signals: QtCore.pyqtSignal):
        super().__init__("SSL Inspector")
        self.signals = signals
        
        # --- Input ---
        ctrl_layout = QtWidgets.QHBoxLayout()
        ctrl_layout.addWidget(QtWidgets.QLabel("Domain:"))
        self.domain_input = QtWidgets.QLineEdit("google.com")
        ctrl_layout.addWidget(self.domain_input)
        self.check_btn = QtWidgets.QPushButton("Check Certificate")
        ctrl_layout.addWidget(self.check_btn)
        ctrl_layout.addStretch()
        self.get_layout().addLayout(ctrl_layout)
        
        # --- Summary Cards ---
        card_layout = QtWidgets.QHBoxLayout()
        self.card_issuer = SummaryCard("Issuer", "---")
        self.card_expiry = SummaryCard("Expires On", "---")
        self.card_days = SummaryCard("Days Remaining", "---")
        
        card_layout.addWidget(self.card_issuer)
        card_layout.addWidget(self.card_expiry)
        card_layout.addWidget(self.card_days)
        self.get_layout().addLayout(card_layout)

        # --- Details Table ---
        self.table = QtWidgets.QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["Field", "Value"])
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.get_layout().addWidget(self.table)
        
        self.check_btn.clicked.connect(self._start)

    def _start(self):
        domain = self.domain_input.text().strip()
        if not domain: return
        self.check_btn.setEnabled(False)
        self.start_scan.emit(domain)

    def show_result(self, info: dict):
        self.check_btn.setEnabled(True)
        self.signals.log.emit('success', f"SSL Check complete for {info['domain']}")
        
        # Update Cards
        self.card_issuer.set_value(info['issuer'])
        self.card_expiry.set_value(info['valid_until'])
        self.card_days.set_value(str(info['days_left']))
        
        # Color Code Expiry
        if info['days_left'] < 30:
            self.card_days.value_label.setStyleSheet("color: #FF4500;") # Red warning
        else:
            self.card_days.value_label.setStyleSheet("color: #00FF00;") # Green good
            
        # Populate Table
        self.table.setRowCount(0)
        rows = [
            ("Common Name", info['common_name']),
            ("Issuer", info['issuer']),
            ("Valid From", info['valid_from']),
            ("Valid Until", info['valid_until']),
            ("Status", "Valid" if info['secure'] else "Insecure")
        ]
        
        for label, val in rows:
            r = self.table.rowCount()
            self.table.insertRow(r)
            self.table.setItem(r, 0, QtWidgets.QTableWidgetItem(str(label)))
            self.table.setItem(r, 1, QtWidgets.QTableWidgetItem(str(val)))

    def show_error(self, msg):
        self.check_btn.setEnabled(True)
        self.signals.log.emit('error', msg)
        QtWidgets.QMessageBox.warning(self, "SSL Error", msg)
