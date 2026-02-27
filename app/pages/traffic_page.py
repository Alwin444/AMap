"""
app/pages/traffic_page.py

The UI for the Packet Sniffer.
FIXES:
- Smart Search: Prioritizes Protocol column if search matches a known protocol name.
- Prevents "TCP" search matching "UDP" packets that have "tcp" in their info text.
"""

from PyQt5 import QtWidgets, QtCore, QtGui
from app.pages.base_page import BasePage
from app.utils.network import get_interfaces

class TrafficPage(BasePage):
    def __init__(self, signals: QtCore.pyqtSignal):
        super().__init__("Packet Sniffer (Live Traffic)")
        self.signals = signals
        self.packets_cache = {} 
        self._counts = {'TCP':0,'UDP':0,'ICMP':0, 'Other':0}

        # --- Controls ---
        ctrl_layout = QtWidgets.QHBoxLayout()
        
        # Interface
        ctrl_layout.addWidget(QtWidgets.QLabel("Interface:"))
        self.iface_combo = QtWidgets.QComboBox()
        self.iface_combo.setMinimumWidth(120)
        ctrl_layout.addWidget(self.iface_combo)
        
        # Display Filter (Search)
        ctrl_layout.addWidget(QtWidgets.QLabel("Search Table:"))
        self.search_input = QtWidgets.QLineEdit()
        self.search_input.setPlaceholderText("Filter (e.g. 192.168, TCP, Alert)...")
        self.search_input.setToolTip("Search currently displayed packets. Matches Protocol column strictly if term is a protocol name.")
        ctrl_layout.addWidget(self.search_input)
        
        # Buttons
        self.start_btn = QtWidgets.QPushButton("Start Capture")
        self.stop_btn = QtWidgets.QPushButton("Stop Capture")
        self.stop_btn.setEnabled(False)
        ctrl_layout.addWidget(self.start_btn)
        ctrl_layout.addWidget(self.stop_btn)
        
        self.get_layout().addLayout(ctrl_layout)
        
        # --- Protocol Stats (Meters) ---
        stats_layout = QtWidgets.QHBoxLayout()
        self.proto_tcp = QtWidgets.QProgressBar(); self.proto_tcp.setFormat('TCP: 0')
        self.proto_udp = QtWidgets.QProgressBar(); self.proto_udp.setFormat('UDP: 0')
        self.proto_icmp = QtWidgets.QProgressBar(); self.proto_icmp.setFormat('ICMP: 0')
        self.proto_other = QtWidgets.QProgressBar(); self.proto_other.setFormat('Other: 0')
        
        self.progress_bars = [self.proto_tcp, self.proto_udp, self.proto_icmp, self.proto_other]
        for w in self.progress_bars:
            w.setRange(0, 100); w.setValue(0); w.setTextVisible(True); w.setFixedHeight(22)
            stats_layout.addWidget(w)
            
        self.get_layout().addLayout(stats_layout)

        # --- Main Splitter ---
        main_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        
        # Added "Alert" column
        self.table = QtWidgets.QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["No", "Time", "Source", "Destination", "Protocol", "Info", "Alert"])
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QtWidgets.QHeaderView.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(5, QtWidgets.QHeaderView.Interactive)
        self.table.setColumnWidth(0, 60)
        self.table.setColumnWidth(5, 350)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        main_splitter.addWidget(self.table)
        
        bottom_splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        
        # Packet Details
        details_group = QtWidgets.QGroupBox("Packet Details")
        details_layout = QtWidgets.QVBoxLayout()
        self.details_tree = QtWidgets.QTreeWidget()
        self.details_tree.setHeaderHidden(True)
        self.details_tree.addTopLevelItem(QtWidgets.QTreeWidgetItem(["Select a packet to see details..."]))
        details_layout.addWidget(self.details_tree)
        details_group.setLayout(details_layout)
        bottom_splitter.addWidget(details_group)
        
        # Packet Bytes
        bytes_group = QtWidgets.QGroupBox("Packet Bytes")
        bytes_layout = QtWidgets.QVBoxLayout()
        self.bytes_text = QtWidgets.QTextEdit()
        self.bytes_text.setReadOnly(True)
        self.bytes_text.setFontFamily("Monospace")
        self.bytes_text.setPlaceholderText("Select a packet to see raw bytes...")
        bytes_layout.addWidget(self.bytes_text)
        bytes_group.setLayout(bytes_layout)
        bottom_splitter.addWidget(bytes_group)
        
        bottom_splitter.setSizes([500, 500])
        main_splitter.addWidget(bottom_splitter)
        main_splitter.setSizes([400, 300]) 
        self.get_layout().addWidget(main_splitter)

        # --- Connections ---
        self.start_btn.clicked.connect(self._start)
        self.stop_btn.clicked.connect(self._stop)
        self.table.itemSelectionChanged.connect(self._select_packet)
        self.search_input.textChanged.connect(self._filter_table)
        
        # Initial Interface Populate
        self._refresh_interfaces()

    def _refresh_interfaces(self):
        try:
            ifaces = get_interfaces()
            if not ifaces: ifaces = ["eth0"]
            self.iface_combo.clear()
            self.iface_combo.addItems(ifaces)
        except:
            self.iface_combo.addItem("eth0")

    def _start(self):
        iface = self.iface_combo.currentText()
        bpf = "" 
        
        self.table.setRowCount(0)
        self.packets_cache = {}
        self._counts = {'TCP':0,'UDP':0,'ICMP':0, 'Other':0}
        for pb in self.progress_bars:
            pb.setValue(0)
            pb.setFormat(f"{pb.text().split(':')[0]}: 0")
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.signals.log.emit('info', f"Capture started on {iface}...")
        
        self.signals.start_capture.emit(iface, bpf)

    def _stop(self):
        self.signals.log.emit('warn', "Capture stop requested by user.")
        self.signals.stop_capture.emit()

    def stop_capture_finished(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.signals.log.emit('success', "Capture finished.")

    def add_packet_row(self, pkt: dict):
        self.packets_cache[pkt['no']] = pkt

        r = self.table.rowCount()
        self.table.insertRow(r)
        
        items = [
            QtWidgets.QTableWidgetItem(str(pkt['no'])),
            QtWidgets.QTableWidgetItem(pkt['time']),
            QtWidgets.QTableWidgetItem(pkt['src']),
            QtWidgets.QTableWidgetItem(pkt['dst']),
            QtWidgets.QTableWidgetItem(pkt['proto']),
            QtWidgets.QTableWidgetItem(pkt['info']),
            QtWidgets.QTableWidgetItem(pkt['alert'] if pkt.get('alert') else "")
        ]

        # Colors
        color_hex = pkt.get('color')
        if color_hex:
            qcolor = QtGui.QColor(color_hex)
            for item in items:
                item.setForeground(qcolor)

        if pkt.get('alert'):
            for item in items:
                item.setBackground(QtGui.QColor("#330000"))
                item.setForeground(QtGui.QColor("#ff5555"))

        for i, item in enumerate(items):
            self.table.setItem(r, i, item)
        
        # Apply current filter immediately
        self._filter_row(r)

        if r > 1000: 
            self.table.removeRow(0)
        if r % 5 == 0: self.table.scrollToBottom()

        # Meters
        proto = pkt['proto'].upper()
        if 'TCP' in proto: self._counts['TCP'] += 1
        elif 'UDP' in proto: self._counts['UDP'] += 1
        elif 'ICMP' in proto: self._counts['ICMP'] += 1
        else: self._counts['Other'] += 1
        
        total = sum(self._counts.values()) or 1
        self.proto_tcp.setValue(int(self._counts['TCP'] / total * 100))
        self.proto_udp.setValue(int(self._counts['UDP'] / total * 100))
        self.proto_icmp.setValue(int(self._counts['ICMP'] / total * 100))
        self.proto_other.setValue(int(self._counts['Other'] / total * 100))
        
        self.proto_tcp.setFormat(f"TCP: {self._counts['TCP']}")
        self.proto_udp.setFormat(f"UDP: {self._counts['UDP']}")
        self.proto_icmp.setFormat(f"ICMP: {self._counts['ICMP']}")
        self.proto_other.setFormat(f"Other: {self._counts['Other']}")

    def _filter_table(self):
        """Hides rows that don't match search text."""
        for r in range(self.table.rowCount()):
            self._filter_row(r)

    def _filter_row(self, r):
        """
        Smart Filter:
        If search term is a known protocol (e.g. 'TCP'), strictly check Protocol column.
        Otherwise, search all columns.
        """
        search_text = self.search_input.text().strip().lower()
        
        if not search_text:
            self.table.setRowHidden(r, False)
            return

        match = False
        
        # Known protocols to enforce strict column matching
        known_protocols = ['tcp', 'udp', 'icmp', 'arp', 'dns', 'http', 'tls', 'ssl', 'ssh']
        
        if search_text in known_protocols:
            # STRICT MODE: Check only Protocol column (Index 4)
            proto_item = self.table.item(r, 4)
            if proto_item and search_text == proto_item.text().lower():
                match = True
        else:
            # NORMAL MODE: Check all relevant columns (Src, Dst, Proto, Info, Alert)
            for c in [2, 3, 4, 5, 6]:
                item = self.table.item(r, c)
                if item and search_text in item.text().lower():
                    match = True
                    break
        
        self.table.setRowHidden(r, not match)

    def _select_packet(self):
        sel = self.table.selectedItems()
        if not sel: return
        
        try:
            row = sel[0].row()
            pkt_no = int(self.table.item(row, 0).text())
        except ValueError:
            return

        if pkt_no not in self.packets_cache:
            return

        pkt = self.packets_cache[pkt_no]
        
        self.details_tree.clear()
        item_frame = QtWidgets.QTreeWidgetItem(self.details_tree, [f"Frame {pkt['no']}: {pkt['info']}"])
        item_eth = QtWidgets.QTreeWidgetItem(item_frame, [f"Ethernet II, Src: {pkt['src']}, Dst: {pkt['dst']}"])
        item_proto = QtWidgets.QTreeWidgetItem(item_frame, [f"Protocol: {pkt['proto']}"])
        
        if pkt.get('alert'):
             item_alert = QtWidgets.QTreeWidgetItem(item_frame, [f"ALERT: {pkt['alert']}"])
             item_alert.setForeground(0, QtGui.QColor("#ff5555"))

        self.details_tree.expandAll()
        
        if 'payload' in pkt and pkt['payload']:
            self.bytes_text.setText(pkt['payload'])
        else:
            self.bytes_text.setText("[No Raw Payload Data]")
