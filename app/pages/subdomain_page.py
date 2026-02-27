"""
app/pages/subdomain_page.py
UI for Subdomain Scanner.
"""
from PyQt5 import QtWidgets, QtCore
from app.pages.base_page import BasePage

class SubdomainPage(BasePage):
    start_scan_signal = QtCore.pyqtSignal(str)

    def __init__(self, signals):
        super().__init__("Subdomain Scanner (OSINT)")
        self.signals = signals
        
        ctrl = QtWidgets.QHBoxLayout()
        self.inp_domain = QtWidgets.QLineEdit("google.com")
        self.btn_scan = QtWidgets.QPushButton("Find Subdomains")
        ctrl.addWidget(self.inp_domain)
        ctrl.addWidget(self.btn_scan)
        self.get_layout().addLayout(ctrl)
        
        self.list_widget = QtWidgets.QListWidget()
        self.get_layout().addWidget(self.list_widget)
        
        self.btn_scan.clicked.connect(self._start)

    def _start(self):
        domain = self.inp_domain.text()
        self.list_widget.clear()
        self.btn_scan.setEnabled(False)
        self.signals.log.emit("info", f"Scanning subdomains for {domain}...")
        self.start_scan_signal.emit(domain)

    def add_sub(self, sub):
        self.list_widget.addItem(sub)

    def finish(self, count):
        self.btn_scan.setEnabled(True)
        self.signals.log.emit("success", f"Found {count} subdomains.")
