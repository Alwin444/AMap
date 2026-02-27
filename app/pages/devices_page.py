"""
app/pages/devices_page.py

The UI for the LAN Device Scanner.
Features:
- Balanced Layout: Larger summary cards for better visibility.
- Visual Feedback: Start button clearly greys out during scan.
- Auto-detects network interfaces.
- Collapsible advanced scan options.
- Safe table handling & IP Sorting.
- CSV Export.
"""

from PyQt5 import QtWidgets, QtCore, QtGui
from app.pages.base_page import BasePage, SummaryCard
from app.utils.network import get_interfaces
from app.utils.persistence import export_to_csv

class NumericTableWidgetItem(QtWidgets.QTableWidgetItem):
    """Custom Item to sort IP addresses correctly."""
    def __lt__(self, other):
        try:
            return [int(x) for x in self.text().split('.')] < [int(x) for x in other.text().split('.')]
        except ValueError:
            return super().__lt__(other)

class DevicesPage(BasePage):
    def __init__(self, signals: QtCore.pyqtSignal):
        super().__init__('LAN Device Scanner')
        self.signals = signals
        self.devices = {} 

        # --- Layout Settings ---
        self.get_layout().setContentsMargins(20, 10, 20, 20)
        self.get_layout().setSpacing(10)

        # --- Compact Title ---
        if hasattr(self, 'title'):
            self.title.setStyleSheet("""
                font-size: 12pt; 
                font-weight: bold; 
                color: #00ff99; 
                padding: 0px; 
                margin-top: 0px;
                margin-bottom: 0px;
            """)
            self.title.setFixedHeight(22)

        # =========================================
        # 1. TOP CONTROL BAR
        # =========================================
        top_row = QtWidgets.QHBoxLayout()
        top_row.setSpacing(15) # More spacing between groups
        
        # Left Side: Scan Controls
        left_controls = QtWidgets.QHBoxLayout()
        left_controls.setSpacing(10)
        left_controls.addWidget(QtWidgets.QLabel('Interface:'))
        
        self.iface_combo = QtWidgets.QComboBox()
        self.iface_combo.setMinimumWidth(150)
        self.iface_combo.setFixedHeight(32)
        left_controls.addWidget(self.iface_combo)
        
        self.scan_btn = QtWidgets.QPushButton('Start Scan')
        self.scan_btn.setFixedSize(120, 32)
        # Added explicit :disabled style for visual feedback
        self.scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #00BFFF; 
                color: white; 
                font-weight: bold;
                border-radius: 4px;
            }
            QPushButton:disabled {
                background-color: #4a5b6c;
                color: #888888;
                border: 1px solid #3d4a59;
            }
        """)
        left_controls.addWidget(self.scan_btn)
        
        self.stop_btn = QtWidgets.QPushButton('Stop')
        self.stop_btn.setFixedSize(80, 32)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #4a5b6c;
                color: white;
                border-radius: 4px;
            }
            QPushButton:enabled {
                background-color: #e74c3c; /* Red when active */
            }
        """)
        left_controls.addWidget(self.stop_btn)
        
        top_row.addLayout(left_controls)
        top_row.addStretch()

        # Right Side: Summary Cards (FIXED: Sized Up)
        self.card_count = SummaryCard('Devices Found', '0')
        self.card_last = SummaryCard('Last Seen', 'N/A')
        
        # Increased size for better visibility
        self.card_count.setFixedSize(180, 80) 
        self.card_last.setFixedSize(180, 80)
        
        top_row.addWidget(self.card_count)
        top_row.addWidget(self.card_last)
        
        self.get_layout().addLayout(top_row)

        # =========================================
        # 2. MAIN CONTENT (SPLITTER)
        # =========================================
        split = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        split.setHandleWidth(1)
        split.setStyleSheet("QSplitter::handle { background-color: #3d4a59; }")
        
        # --- Left: Device Table ---
        self.table = QtWidgets.QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(['IP', 'MAC', 'Vendor', 'Hostname', 'Last Seen'])
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QtWidgets.QHeaderView.Interactive)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.verticalHeader().setVisible(False) 
        self.table.setShowGrid(False)
        self.table.verticalHeader().setDefaultSectionSize(28) 
        
        # Table Stylesheet
        self.table.setStyleSheet("""
            QTableWidget { 
                border: 1px solid #3d4a59; 
                background-color: #0b1d2e; 
                alternate-background-color: #132638; 
                color: #e6f7ff;
                gridline-color: #1e3b4d;
            }
            QTableWidget::item:selected {
                background-color: rgba(0, 255, 153, 0.2);
                color: #ffffff;
            }
            QTableWidget::item:hover {
                background-color: rgba(255, 255, 255, 0.05);
            }
            QHeaderView::section {
                background-color: #0f2a3a;
                color: #00ff99;
                border: none;
                padding: 4px;
                font-weight: bold;
            }
            QTableCornerButton::section {
                background-color: #0f2a3a;
                border: 1px solid #3d4a59;
            }
        """)
        
        split.addWidget(self.table)

        # --- Right: Details Panel ---
        detail_frame = QtWidgets.QFrame()
        detail_frame.setStyleSheet("QFrame { background-color: rgba(255,255,255,0.02); border-radius: 6px; }")
        dv_layout = QtWidgets.QVBoxLayout(detail_frame)
        dv_layout.setContentsMargins(15, 15, 15, 15)
        dv_layout.setSpacing(10)
        
        self.details_box = QtWidgets.QGroupBox('Selected Device Details')
        self.details_box.setStyleSheet("QGroupBox { font-weight: bold; font-size: 11pt; border: none; color: #00ff99; }")
        form = QtWidgets.QFormLayout()
        form.setSpacing(8)
        
        self.lbl_ip = QtWidgets.QLabel('---')
        self.lbl_mac = QtWidgets.QLabel('---')
        self.lbl_vendor = QtWidgets.QLabel('---')
        self.lbl_hostname = QtWidgets.QLabel('---')
        
        for lbl in [self.lbl_ip, self.lbl_mac, self.lbl_vendor, self.lbl_hostname]:
            lbl.setStyleSheet("color: #e6f7ff; font-weight: normal;")
            lbl.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)

        form.addRow('IP Address:', self.lbl_ip)
        form.addRow('MAC Address:', self.lbl_mac)
        form.addRow('Vendor:', self.lbl_vendor)
        form.addRow('Hostname:', self.lbl_hostname)
        self.details_box.setLayout(form)
        dv_layout.addWidget(self.details_box)
        
        dv_layout.addStretch()

        # Action Buttons
        actions_group = QtWidgets.QWidget()
        actions_layout = QtWidgets.QVBoxLayout(actions_group)
        actions_layout.setContentsMargins(0,0,0,0)
        actions_layout.setSpacing(10)
        
        self.port_scan_btn = QtWidgets.QPushButton('Quick Port Scan')
        self.port_scan_btn.setMinimumHeight(36)
        self.port_scan_btn.setCursor(QtCore.Qt.PointingHandCursor)
        
        self.export_btn = QtWidgets.QPushButton('Export List to CSV')
        self.export_btn.setMinimumHeight(36)
        self.export_btn.setCursor(QtCore.Qt.PointingHandCursor)
        
        actions_layout.addWidget(self.port_scan_btn)
        actions_layout.addWidget(self.export_btn)
        dv_layout.addWidget(actions_group)
        
        split.addWidget(detail_frame)
        split.setSizes([900, 300]) 
        
        # Add stretch factor 1 to split
        self.get_layout().addWidget(split, 1)
        
        # =========================================
        # 3. BOTTOM: ADVANCED OPTIONS
        # =========================================
        self.adv_panel = QtWidgets.QGroupBox('Advanced Scan Options')
        self.adv_panel.setCheckable(True)
        self.adv_panel.setChecked(False)
        self.adv_panel.setStyleSheet("QGroupBox { margin-top: 5px; font-weight: bold; padding-top: 5px; color: #00ff99; }")
        
        self.adv_container = QtWidgets.QWidget()
        self.adv_container.setVisible(False)
        
        adv_layout = QtWidgets.QHBoxLayout(self.adv_container)
        adv_layout.setContentsMargins(10, 10, 10, 10)
        
        self.scan_range_input = QtWidgets.QLineEdit("192.168.1.0/24")
        self.scan_range_input.setFixedWidth(200)
        adv_layout.addWidget(QtWidgets.QLabel("Target Range:"))
        adv_layout.addWidget(self.scan_range_input)
        
        adv_layout.addSpacing(20)
        
        self.nmap_check = QtWidgets.QCheckBox("Use Nmap Engine (Slower but more accurate)")
        self.nmap_check.setChecked(True) 
        adv_layout.addWidget(self.nmap_check)
        adv_layout.addStretch()
        
        gb_layout = QtWidgets.QVBoxLayout(self.adv_panel)
        gb_layout.setContentsMargins(2, 2, 2, 2)
        gb_layout.addWidget(self.adv_container)
        
        self.get_layout().addWidget(self.adv_panel)

        # --- Connections ---
        self.scan_btn.clicked.connect(self._start_scan)
        self.stop_btn.clicked.connect(self._stop_scan)
        self.table.itemSelectionChanged.connect(self._select)
        self.port_scan_btn.clicked.connect(self._quick_port_scan)
        self.export_btn.clicked.connect(self._export_csv)
        self.adv_panel.toggled.connect(self.adv_container.setVisible)
        
        # --- Auto-Refresh Interfaces Timer ---
        self._refresh_timer = QtCore.QTimer(self)
        self._refresh_timer.setInterval(5000)
        self._refresh_timer.timeout.connect(self._refresh_interfaces)
        self._refresh_timer.start()
        
        self._refresh_interfaces()
        
    def _refresh_interfaces(self):
        try:
            new_ifaces = get_interfaces()
            if not new_ifaces: new_ifaces = ["eth0"]
            current = [self.iface_combo.itemText(i) for i in range(self.iface_combo.count())]
            if set(new_ifaces) != set(current):
                sel = self.iface_combo.currentText()
                self.iface_combo.clear()
                self.iface_combo.addItems(new_ifaces)
                if sel in new_ifaces: self.iface_combo.setCurrentText(sel)
        except: pass

    def _start_scan(self):
        iface = self.iface_combo.currentText()
        ip_range = self.scan_range_input.text()
        use_nmap = self.adv_panel.isChecked() and self.nmap_check.isChecked()
        
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self.devices = {}
        self.card_count.set_value('0')
        self.card_last.set_value('N/A')
        
        scan_type = "Nmap" if use_nmap else "ARP"
        self.signals.log.emit('info', f'{scan_type} scan started on {iface} for {ip_range}...')
        self.signals.start_arp_scan.emit(iface, ip_range, use_nmap)

    def _stop_scan(self):
        self.signals.log.emit('warn', 'Scan stopped by user.')
        self.signals.stop_arp_scan.emit()

    def add_device(self, dev: dict):
        self.devices[dev['ip']] = dev
        
        row_match = None
        for r in range(self.table.rowCount()):
            item = self.table.item(r, 0)
            if item and item.text() == dev['ip']:
                row_match = r
                break
        
        if row_match is None:
            r = self.table.rowCount()
            self.table.insertRow(r)
            row_match = r
        
        self.table.setItem(row_match, 0, NumericTableWidgetItem(str(dev.get('ip', ''))))
        self.table.setItem(row_match, 1, QtWidgets.QTableWidgetItem(str(dev.get('mac', 'Unknown'))))
        self.table.setItem(row_match, 2, QtWidgets.QTableWidgetItem(str(dev.get('vendor', 'Unknown'))))
        self.table.setItem(row_match, 3, QtWidgets.QTableWidgetItem(str(dev.get('hostname', 'Unknown'))))
        self.table.setItem(row_match, 4, QtWidgets.QTableWidgetItem(str(dev.get('seen', ''))))
        
        self.card_count.set_value(str(self.table.rowCount()))
        self.card_last.set_value(dev.get('seen', 'N/A'))

    def scan_finished(self):
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.table.setSortingEnabled(True)
        self.signals.log.emit('success', f'Scan finished. Found {self.table.rowCount()} devices.')

    def _select(self):
        sel = self.table.selectedItems()
        if not sel: return
        row = sel[0].row()
        
        def get_text(col):
            item = self.table.item(row, col)
            return item.text() if item else "---"

        self.lbl_ip.setText(get_text(0))
        self.lbl_mac.setText(get_text(1))
        self.lbl_vendor.setText(get_text(2))
        self.lbl_hostname.setText(get_text(3))

    def _quick_port_scan(self):
        if self.lbl_ip.text() in ['---', '']:
            self.signals.log.emit('error', 'No device selected.')
            return
        self.signals.log.emit('info', f'Port scan requested for {self.lbl_ip.text()}...')
        self.signals.start_port_scan.emit(self.lbl_ip.text(), "22,80,443,8080")

    def _export_csv(self):
        if not self.devices:
            self.signals.log.emit('warn', 'No devices to export.')
            return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export", "devices.csv", "CSV (*.csv)")
        if path:
            export_to_csv(list(self.devices.values()), ['ip','mac','vendor','hostname','seen'], path)
            self.signals.log.emit('success', f"Saved to {path}")
