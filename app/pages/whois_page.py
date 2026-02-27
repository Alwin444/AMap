"""
app/pages/whois_page.py

The UI for Domain WHOIS Lookup.
FIXED: Added missing pyqtSignal import.
Features: Professional layout, sized-up controls.
"""

from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtCore import pyqtSignal # Crucial import
from app.pages.base_page import BasePage

class WhoisPage(BasePage):
    start_lookup = pyqtSignal(str)

    def __init__(self, signals: QtCore.pyqtSignal):
        super().__init__("WHOIS Lookup")
        self.signals = signals
        
        # Layout Settings
        self.get_layout().setContentsMargins(20, 20, 20, 20)
        self.get_layout().setSpacing(15)
        
        # --- Controls ---
        ctrl_layout = QtWidgets.QHBoxLayout()
        ctrl_layout.setSpacing(10)
        
        ctrl_layout.addWidget(QtWidgets.QLabel("Domain:"))
        
        self.domain_input = QtWidgets.QLineEdit("google.com")
        self.domain_input.setPlaceholderText("e.g. google.com, example.org")
        self.domain_input.setMinimumHeight(35)
        self.domain_input.setStyleSheet("font-size: 11pt;")
        ctrl_layout.addWidget(self.domain_input)
        
        self.run_btn = QtWidgets.QPushButton("Get WHOIS Data")
        self.run_btn.setMinimumHeight(35)
        self.run_btn.setMinimumWidth(150)
        self.run_btn.setStyleSheet("""
            QPushButton { 
                background-color: #00BFFF; 
                color: white; 
                font-size: 11pt; 
                font-weight: bold; 
                border-radius: 6px; 
            }
            QPushButton:hover { background-color: #00AADD; }
            QPushButton:disabled { background-color: #555; }
        """)
        ctrl_layout.addWidget(self.run_btn)
        
        self.get_layout().addLayout(ctrl_layout)
        
        # --- Results Area ---
        results_group = QtWidgets.QGroupBox("Registration Data")
        results_group.setStyleSheet("QGroupBox { font-weight: bold; font-size: 11pt; }")
        results_layout = QtWidgets.QVBoxLayout()
        
        self.text_area = QtWidgets.QTextEdit()
        self.text_area.setReadOnly(True)
        self.text_area.setFontFamily("Monospace")
        self.text_area.setPlaceholderText("WHOIS data will appear here...")
        self.text_area.setStyleSheet("""
            QTextEdit {
                background-color: #0a1525;
                color: #00ff99;
                border: 1px solid #3d4a59;
                font-size: 10pt;
                padding: 8px;
            }
        """)
        
        results_layout.addWidget(self.text_area)
        results_group.setLayout(results_layout)
        
        self.get_layout().addWidget(results_group)
        
        # --- Connections ---
        self.run_btn.clicked.connect(self._run)
        self.domain_input.returnPressed.connect(self._run)

    def _run(self):
        domain = self.domain_input.text().strip()
        if not domain: 
            self.signals.log.emit('error', "Please enter a domain.")
            return
            
        self.run_btn.setEnabled(False)
        self.text_area.setText("Querying WHOIS database... (This may take a few seconds)")
        self.start_lookup.emit(domain)

    def show_result(self, data: str):
        self.run_btn.setEnabled(True)
        self.text_area.setText(data)
        self.signals.log.emit('success', "WHOIS lookup finished.")

    def show_error(self, msg):
        self.run_btn.setEnabled(True)
        self.text_area.setText(f"Error: {msg}")
        self.signals.log.emit('error', msg)
