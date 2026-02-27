"""
app/pages/traceroute_page.py
UI for Traceroute.
"""
from PyQt5 import QtWidgets, QtCore
from app.pages.base_page import BasePage, SummaryCard

class TraceroutePage(BasePage):
    start_trace_signal = QtCore.pyqtSignal(str)

    def __init__(self, signals):
        super().__init__("Network Traceroute")
        self.signals = signals
        
        # Controls
        ctrl = QtWidgets.QHBoxLayout()
        ctrl.addWidget(QtWidgets.QLabel("Target:"))
        self.target_input = QtWidgets.QLineEdit("8.8.8.8")
        self.target_input.setPlaceholderText("Domain or IP")
        ctrl.addWidget(self.target_input)
        self.btn_start = QtWidgets.QPushButton("Trace Route")
        ctrl.addWidget(self.btn_start)
        self.get_layout().addLayout(ctrl)
        
        # Table
        self.table = QtWidgets.QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Hop", "IP Address", "Latency"])
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.get_layout().addWidget(self.table)
        
        self.btn_start.clicked.connect(self._start)

    def _start(self):
        target = self.target_input.text().strip()
        if not target: return
        self.table.setRowCount(0)
        self.btn_start.setEnabled(False)
        self.signals.log.emit("info", f"Tracing route to {target}...")
        self.start_trace_signal.emit(target)

    def add_hop(self, hop, ip, rtt):
        r = self.table.rowCount()
        self.table.insertRow(r)
        self.table.setItem(r, 0, QtWidgets.QTableWidgetItem(str(hop)))
        self.table.setItem(r, 1, QtWidgets.QTableWidgetItem(ip))
        self.table.setItem(r, 2, QtWidgets.QTableWidgetItem(rtt))
        self.table.scrollToBottom()

    def finish_trace(self):
        self.btn_start.setEnabled(True)
        self.signals.log.emit("success", "Traceroute finished.")
