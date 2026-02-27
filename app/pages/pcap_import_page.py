"""
app/pages/pcap_import_page.py

The UI for the PCAP Importer.
Features:
- Loads .pcap files using a background worker.
- Displays packet details and hex dump.
- Exports loaded packets to CSV.
"""

from PyQt5 import QtWidgets, QtCore, QtGui
from app.pages.base_page import BasePage
from app.workers.pcap_worker import PcapLoaderWorker
from app.utils.persistence import export_to_csv
import os

class PcapImportPage(BasePage):
    def __init__(self, signals: QtCore.pyqtSignal):
        super().__init__("PCAP Import & Analyzer")
        self.signals = signals
        self.worker = None
        self.loaded_packets = {} # Cache for details view: {row_number: packet_dict}
        
        # --- Controls ---
        ctrl_layout = QtWidgets.QHBoxLayout()
        self.open_btn = QtWidgets.QPushButton("Open .pcap File")
        ctrl_layout.addWidget(self.open_btn)
        
        self.file_label = QtWidgets.QLabel("No file loaded.")
        # Ellide text if too long
        self.file_label.setStyleSheet("color: #888;")
        ctrl_layout.addWidget(self.file_label)
        
        ctrl_layout.addStretch()
        
        self.export_btn = QtWidgets.QPushButton("Export to CSV")
        self.export_btn.setEnabled(False) # Disabled until data loaded
        ctrl_layout.addWidget(self.export_btn)
        
        self.get_layout().addLayout(ctrl_layout)
        
        # --- Main Vertical Splitter ---
        main_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        
        self.table = QtWidgets.QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["No", "Time", "Source", "Destination", "Protocol", "Info"])
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QtWidgets.QHeaderView.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(5, QtWidgets.QHeaderView.Interactive)
        self.table.setColumnWidth(0, 70)
        self.table.setColumnWidth(5, 300)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        main_splitter.addWidget(self.table)
        
        bottom_splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        
        # Details Tree
        details_group = QtWidgets.QGroupBox("Packet Details")
        details_layout = QtWidgets.QVBoxLayout()
        self.details_tree = QtWidgets.QTreeWidget()
        self.details_tree.setHeaderHidden(True)
        self.details_tree.addTopLevelItem(QtWidgets.QTreeWidgetItem(["Select a packet to see details..."]))
        details_layout.addWidget(self.details_tree)
        details_group.setLayout(details_layout)
        bottom_splitter.addWidget(details_group)
        
        # Hex View
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
        self.open_btn.clicked.connect(self._open_file)
        self.export_btn.clicked.connect(self._export_csv)
        self.table.itemSelectionChanged.connect(self._select_packet)

    def _open_file(self):
        options = QtWidgets.QFileDialog.Options()
        # Start in 'data' directory if it exists
        start_dir = "data" if os.path.exists("data") else ""
        
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Open PCAP File", start_dir, "PCAP Files (*.pcap *.pcapng);;All Files (*)", options=options
        )
        
        if file_path:
            self.file_label.setText(os.path.basename(file_path))
            self.signals.log.emit('info', f"Loading {file_path}...")
            self._start_worker(file_path)

    def _start_worker(self, filename):
        self.table.setRowCount(0)
        self.loaded_packets = {}
        self.open_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        
        self.worker = PcapLoaderWorker(filename)
        self.worker.packet_read.connect(self._add_packet)
        self.worker.finished.connect(self._load_finished)
        self.worker.error_occurred.connect(self._on_error)
        self.worker.start()

    def _add_packet(self, pkt):
        # Store in cache
        self.loaded_packets[pkt['no']] = pkt
        
        r = self.table.rowCount()
        self.table.insertRow(r)
        
        items = [
            QtWidgets.QTableWidgetItem(str(pkt['no'])),
            QtWidgets.QTableWidgetItem(pkt['time']),
            QtWidgets.QTableWidgetItem(pkt['src']),
            QtWidgets.QTableWidgetItem(pkt['dst']),
            QtWidgets.QTableWidgetItem(pkt['proto']),
            QtWidgets.QTableWidgetItem(pkt['info'])
        ]
        
        # Apply Color Coding
        color_hex = pkt.get('color')
        if color_hex:
            qcolor = QtGui.QColor(color_hex)
            for item in items:
                item.setForeground(qcolor)

        for i, item in enumerate(items):
            self.table.setItem(r, i, item)

    def _load_finished(self):
        self.open_btn.setEnabled(True)
        self.export_btn.setEnabled(True)
        self.signals.log.emit('success', f"Finished loading. {self.table.rowCount()} packets found.")

    def _on_error(self, msg):
        self.open_btn.setEnabled(True)
        self.signals.log.emit('error', f"PCAP Load Error: {msg}")

    def _select_packet(self):
        sel = self.table.selectedItems()
        if not sel: return
        
        try:
            row = sel[0].row()
            pkt_no = int(self.table.item(row, 0).text())
        except ValueError:
            return

        if pkt_no not in self.loaded_packets:
            return

        pkt = self.loaded_packets[pkt_no]
        
        # Populate Tree
        self.details_tree.clear()
        item_frame = QtWidgets.QTreeWidgetItem(self.details_tree, [f"Frame {pkt['no']}: {pkt['info']}"])
        QtWidgets.QTreeWidgetItem(item_frame, [f"Time: {pkt['time']}"])
        
        item_net = QtWidgets.QTreeWidgetItem(item_frame, [f"Network: {pkt['src']} -> {pkt['dst']}"])
        QtWidgets.QTreeWidgetItem(item_net, [f"Protocol: {pkt['proto']}"])
        
        self.details_tree.expandAll()
        
        # Populate Hex
        if pkt.get('payload'):
            self.bytes_text.setText(pkt['payload'])
        else:
            self.bytes_text.setText("[No payload data]")

    def _export_csv(self):
        if not self.loaded_packets:
            self.signals.log.emit('warn', "No data to export.")
            return

        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export PCAP Data", "pcap_export.csv", "CSV Files (*.csv)")
        if not path:
            return

        # Convert dict values to list for export
        data_list = list(self.loaded_packets.values())
        headers = ['no', 'time', 'src', 'dst', 'proto', 'info']
        
        if export_to_csv(data_list, headers, path):
            self.signals.log.emit('success', f"Exported to {path}")
        else:
            self.signals.log.emit('error', "Failed to export CSV.")
