"""
app/pages/dns_lookup_page.py

The UI for the DNS Lookup tool.
Features:
- Input for Domain and Record Type (A, MX, etc).
- Connects to backend worker via signal.
- Displays results in a 'dig'-like format.
- Professional Layout: Sized-up controls.
- No Word Wrap for better alignment.
"""

from PyQt5 import QtWidgets, QtCore, QtGui
from app.pages.base_page import BasePage, SummaryCard

class DNSLookupPage(BasePage):
    # Signal to Main Window: (domain_or_ip, record_type)
    start_lookup_signal = QtCore.pyqtSignal(str, str)

    def __init__(self, signals: QtCore.pyqtSignal):
        super().__init__("DNS Lookup")
        self.signals = signals
        
        # Layout
        self.get_layout().setContentsMargins(20, 20, 20, 20)
        self.get_layout().setSpacing(15)
        
        # --- Controls ---
        ctrl_layout = QtWidgets.QHBoxLayout()
        ctrl_layout.setSpacing(10)
        
        ctrl_layout.addWidget(QtWidgets.QLabel("Target:"))
        
        self.domain_input = QtWidgets.QLineEdit("google.com")
        self.domain_input.setPlaceholderText("Enter domain (eg: google.com)")
        self.domain_input.setMinimumHeight(35)
        self.domain_input.setStyleSheet("font-size: 11pt;")
        ctrl_layout.addWidget(self.domain_input)
        
        self.record_type = QtWidgets.QComboBox()
        # Added 'ALL' option
        self.record_type.addItems(["A", "AAAA", "MX", "NS", "TXT", "ALL"])
        self.record_type.setMinimumHeight(35)
        self.record_type.setMinimumWidth(100)
        ctrl_layout.addWidget(self.record_type)
        
        self.lookup_btn = QtWidgets.QPushButton("Lookup")
        self.lookup_btn.setMinimumHeight(35)
        self.lookup_btn.setMinimumWidth(100)
        self.lookup_btn.setStyleSheet("""
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
        ctrl_layout.addWidget(self.lookup_btn)
        
        # ctrl_layout.addStretch() # Stretch handled by input field mostly
        self.get_layout().addLayout(ctrl_layout)
        
        # --- Results Area ---
        results_group = QtWidgets.QGroupBox("Query Results")
        results_group.setStyleSheet("QGroupBox { font-weight: bold; font-size: 11pt; }")
        results_layout = QtWidgets.QVBoxLayout()
        
        self.results_text = QtWidgets.QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setFontFamily("Monospace") # Essential for alignment
        self.results_text.setLineWrapMode(QtWidgets.QTextEdit.NoWrap) # Disable wrapping
        self.results_text.setPlaceholderText("DNS query results will appear here...")
        self.results_text.setStyleSheet("""
            QTextEdit {
                background-color: #0a1525;
                color: #00ff99;
                border: 1px solid #3d4a59;
                font-size: 10pt;
                padding: 8px;
            }
        """)
        
        results_layout.addWidget(self.results_text)
        results_group.setLayout(results_layout)
        
        self.get_layout().addWidget(results_group)
        
        # --- Connections ---
        self.lookup_btn.clicked.connect(self._run_lookup)
        # Trigger lookup on Enter key
        self.domain_input.returnPressed.connect(self._run_lookup)

    def _run_lookup(self):
        target = self.domain_input.text().strip()
        rectype = self.record_type.currentText()
        
        if not target:
            self.signals.log.emit('error', "Please enter a target.")
            return
            
        self.signals.log.emit('info', f"Lookup requested for {target} ({rectype})...")
        self.results_text.setText("Querying...")
        self.lookup_btn.setEnabled(False)
        
        # Emit custom signal to Main Window to start the worker
        self.start_lookup_signal.emit(target, rectype)
        
    def show_results(self, text: str):
        """Public slot for worker to show results."""
        self.lookup_btn.setEnabled(True)
        self.results_text.setText(text)
        self.signals.log.emit('success', "DNS Lookup finished.")
        
    def show_error(self, message: str):
        """Public slot for worker error reporting."""
        self.lookup_btn.setEnabled(True)
        self.results_text.setText(f"Error: {message}")
        self.signals.log.emit('error', f"DNS Error: {message}")
