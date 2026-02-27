"""
app/pages/port_scan_page.py

The UI for the Port Scanner.
FIXED: Added 'Sl. No' column to clearly show row count vs port number.
"""

from PyQt5 import QtWidgets, QtCore, QtGui
from app.pages.base_page import BasePage, SummaryCard

class PortsPage(BasePage):
    def __init__(self, signals: QtCore.pyqtSignal):
        super().__init__("Port Scanner")
        self.signals = signals
        self.open_ports = 0
        
        # --- Controls ---
        ctrl_layout = QtWidgets.QHBoxLayout()
        ctrl_layout.addWidget(QtWidgets.QLabel("Target IP:"))
        self.target_ip = QtWidgets.QLineEdit()
        self.target_ip.setPlaceholderText("e.g., 192.168.1.1")
        ctrl_layout.addWidget(self.target_ip)
        
        ctrl_layout.addWidget(QtWidgets.QLabel("Ports (csv/range):"))
        self.ports = QtWidgets.QLineEdit("21,22,80,443,1000-2000")
        self.ports.setPlaceholderText("e.g. 21, 80, 1000-2000 (Empty = All)")
        self.ports.setToolTip("Enter individual ports separated by commas, or ranges with a hyphen.\nExample: 22, 80, 8080-8090")
        ctrl_layout.addWidget(self.ports)
        
        self.scan_btn = QtWidgets.QPushButton("Scan Ports")
        self.stop_btn = QtWidgets.QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        
        # Filter Checkbox
        self.filter_check = QtWidgets.QCheckBox("Show Open Ports Only")
        self.filter_check.setChecked(False)
        self.filter_check.setToolTip("Hide closed/refused ports from the list")
        
        ctrl_layout.addWidget(self.scan_btn)
        ctrl_layout.addWidget(self.stop_btn)
        ctrl_layout.addWidget(self.filter_check)
        self.get_layout().addLayout(ctrl_layout)

        # --- Summary Cards ---
        card_layout = QtWidgets.QHBoxLayout()
        self.card_target = SummaryCard("Current Target", "N/A")
        self.card_open = SummaryCard("Open Ports", "0")
        self.card_status = SummaryCard("Status", "Idle")
        card_layout.addWidget(self.card_target)
        card_layout.addWidget(self.card_open)
        card_layout.addWidget(self.card_status)
        self.get_layout().addLayout(card_layout)

        # --- Results Table ---
        # Changed to 5 columns to include Sl. No
        self.table = QtWidgets.QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["SI No.", "Host", "Port", "Status", "Service/Banner"])
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        
        # Resize the Sl. No column to be smaller
        self.table.horizontalHeader().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        
        # Hide default vertical row numbers (we use Sl. No column instead)
        self.table.verticalHeader().setVisible(False)
        
        self.get_layout().addWidget(self.table)

        # --- Connections ---
        self.scan_btn.clicked.connect(self._start_scan)
        self.stop_btn.clicked.connect(self._stop_scan)
        self.filter_check.toggled.connect(self._apply_filter)

    def _start_scan(self):
        target = self.target_ip.text()
        if not target:
            self.signals.log.emit('error', "No target IP specified.")
            return
            
        ports_str = self.ports.text()
        
        self.table.setRowCount(0)
        self.open_ports = 0
        self.card_target.set_value(target)
        self.card_open.set_value("0")
        self.card_status.set_value("Scanning...")
        
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        
        self.signals.log.emit('info', f"Starting port scan on {target}...")
        self.signals.start_port_scan.emit(target, ports_str)

    def _stop_scan(self):
        self.signals.log.emit('warn', "Port scan stop requested.")
        self.signals.stop_port_scan.emit()

    def add_result(self, res: dict):
        """Public slot for worker to add a port result."""
        r = self.table.rowCount()
        self.table.insertRow(r)
        
        # Col 0: Sl. No (Row Index + 1)
        self.table.setItem(r, 0, QtWidgets.QTableWidgetItem(str(r + 1)))
        
        # Col 1: Host
        self.table.setItem(r, 1, QtWidgets.QTableWidgetItem(res['host']))
        
        # Col 2: Port
        self.table.setItem(r, 2, QtWidgets.QTableWidgetItem(str(res['port'])))
        
        # Col 3: Status
        item = QtWidgets.QTableWidgetItem(res['status'])
        if res['status'] == 'Open':
            item.setForeground(QtGui.QColor("#00FF00")) # Green
            self.open_ports += 1
            self.card_open.set_value(str(self.open_ports))
        elif res['status'] == 'Error':
            item.setForeground(QtGui.QColor("#FF4500")) # Red
        self.table.setItem(r, 3, item)
        
        # Col 4: Banner
        self.table.setItem(r, 4, QtWidgets.QTableWidgetItem(res['banner']))
        
        # Apply filter immediately
        self._apply_filter_to_row(r)
        
        self.table.scrollToBottom()

    def _apply_filter(self):
        """Hides/Shows rows based on checkbox state."""
        for r in range(self.table.rowCount()):
            self._apply_filter_to_row(r)

    def _apply_filter_to_row(self, row):
        """Helper to hide a specific row if it doesn't match the filter."""
        if self.filter_check.isChecked():
            # Status is now at column index 3
            status_item = self.table.item(row, 3)
            if status_item and status_item.text() != "Open":
                self.table.setRowHidden(row, True)
            else:
                self.table.setRowHidden(row, False)
        else:
            self.table.setRowHidden(row, False)

    def scan_finished(self):
        self.card_status.set_value("Finished")
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.signals.log.emit('success', f"Port scan on {self.target_ip.text()} finished.")
        
    def set_target(self, ip: str, ports: str):
        self.target_ip.setText(ip)
        self.ports.setText(ports)
