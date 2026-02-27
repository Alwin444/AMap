"""
wifi_manager_gui.py


This version contains NO simulators or demo data. It is a clean scaffold.

Run: python3 wifi_manager_gui.py
"""

from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtCore import pyqtSignal, QTimer
import sys, time, random

# --- Lighter "Cyber" Gradient Stylesheet ---
CYBER_STYLESHEET = r"""
QWidget {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
        stop:0 #071028, stop:0.5 #0f2a3a, stop:1 #1b3b4d);
    color: #e6f7ff;
    font-family: 'Segoe UI', 'Arial';
    font-size: 10pt;
}
QMainWindow { background: transparent; }

/* Menu, Status, ToolBar */
QMenuBar {
    background-color: rgba(10,30,45,0.85);
    color: #e6f7ff;
}
QMenuBar::item:selected { background: rgba(0,255,153,0.1); }
QMenu { background: #0f2a3a; border: 1px solid rgba(0,255,153,0.1); }
QMenu::item:selected { background: rgba(0,255,153,0.1); }
QStatusBar {
    background: rgba(10,30,45,0.9);
    color: #00ff99;
    font-weight: bold;
}
QStatusBar::item { border: none; padding: 0 8px; }
QToolBar { background: rgba(10,30,45,0.85); border: none; }
QToolBar QToolButton { color: #e6f7ff; padding: 6px; }
QToolBar QToolButton:hover { background: rgba(0,255,153,0.1); }
QToolBar QToolButton:disabled { color: #555; }

/* Left nav */
QListWidget { 
    background: rgba(10,30,45,0.85); 
    border: none; 
    font-size: 11pt; 
    padding-top: 8px; 
    icon-size: 20px; 
}
QListWidget::item { 
    padding: 12px 18px; 
    margin: 2px 6px; 
    border-radius: 6px; 
}
QListWidget::item:hover { background: rgba(0,255,153,0.06); }
QListWidget::item:selected { 
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #002b2b, stop:1 #005f3f); 
    color: #b9fff0; 
}

/* Page Title */
QLabel#PageTitle { 
    font-weight: 700; 
    font-size: 15pt; 
    color: #00ff99; 
    padding-bottom: 6px; 
}

/* Summary cards */
QFrame.card { 
    background: rgba(255,255,255,0.03); 
    border: 1px solid rgba(0,255,153,0.08); 
    border-radius: 8px; 
    padding: 10px; 
}
QLabel.card-title { color: #bfffe1; font-weight: 600; font-size: 9pt; }
QLabel.card-value { color: #e6fff4; font-size: 14pt; font-weight: 700; }

/* Buttons */
QPushButton { 
    background: rgba(0,255,153,0.10); 
    color: #dfffe9; 
    border: 1px solid rgba(0,255,153,0.12); 
    padding: 8px 14px; 
    border-radius: 6px; 
    font-weight: bold;
}
QPushButton:hover { background: rgba(0,255,153,0.14); }
QPushButton:pressed { background: rgba(0,255,153,0.08); }
QPushButton:disabled { background: rgba(255,255,255,0.02); color: #555; }

/* Inputs */
QLineEdit, QTextEdit { 
    background: rgba(255,255,255,0.02); 
    border: 1px solid rgba(0,255,153,0.06); 
    padding: 6px; 
    border-radius: 6px; 
    color: #e6f7ff; 
}
QLineEdit:focus, QTextEdit:focus {
    border: 1px solid #00ff99;
}
QComboBox { background: rgba(255,255,255,0.02); border: 1px solid rgba(0,255,153,0.06); padding: 6px; border-radius: 6px; }
QComboBox QAbstractItemView { background: #0f2a3a; color: #e6f7ff; selection-background-color: #005f3f; }

/* Table widgets */
QTableWidget { 
    background: rgba(255,255,255,0.02); 
    border: 1px solid rgba(0,255,153,0.05); 
    gridline-color: rgba(0,255,153,0.05);
}
QHeaderView::section { 
    background: rgba(0,255,153,0.03); 
    color: #dfffe9; 
    padding: 6px; 
    border: none; 
    font-weight: bold;
}

/* Tree Widget */
QTreeWidget { background: rgba(255,255,255,0.02); border: 1px solid rgba(0,255,153,0.05); }
QTreeWidget::item:selected { background: #005f3f; color: #b9fff0; }

/* GroupBox */
QGroupBox { 
    border: 1px solid rgba(0,255,153,0.1); 
    border-radius: 6px; 
    margin-top: 10px; 
    font-weight: bold; 
}
QGroupBox::title { 
    subcontrol-origin: margin; 
    subcontrol-position: top left; 
    padding: 0 5px; 
    color: #00ff99; 
}
QGroupBox[checkable="true"]::indicator {
    padding: 4px;
}

/* Splitter */
QSplitter::handle { background-color: rgba(0,255,153,0.05); height: 4px; width: 4px; }
QSplitter::handle:hover { background-color: #00ff99; }

/* Dock & log */
QDockWidget { background: rgba(5,15,25,0.85); color: #e6f7ff; font-weight: bold; }
QDockWidget::title {
    background: #0f2a3a;
    padding: 6px;
    color: #00ff99;
}
QTextEdit#GlobalLog {
    background: #050a12;
    color: #00ff99;
    font-family: 'Monospace', 'Courier New';
    font-size: 9pt;
    border: 1px solid rgba(0,255,153,0.1);
}

/* Progress Bar */
QProgressBar {
    border: 1px solid rgba(0,255,153,0.2);
    border-radius: 4px;
    text-align: center;
    color: #e6f7ff;
    background-color: rgba(255,255,255,0.02);
}
QProgressBar::chunk {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #005f3f, stop:1 #00ff99);
    border-radius: 4px;
}
"""

# --- Signals ---
class GUISignals(QtCore.QObject):
    start_arp_scan = pyqtSignal(str)
    start_capture = pyqtSignal(str, str)
    stop_capture = pyqtSignal()
    start_port_scan = pyqtSignal(str, str)
    start_speed_test = pyqtSignal()
    start_wifi_scan = pyqtSignal()
    log = pyqtSignal(str, str) # level, message



# --- Utility small widget: summary card ---
class SummaryCard(QtWidgets.QFrame):
    def __init__(self, title: str, value: str, parent=None):
        super().__init__(parent)
        self.setObjectName('card')
        self.setProperty('class', 'card') # For QSS
        self.setMinimumHeight(70)
        layout = QtWidgets.QVBoxLayout(self)
        t = QtWidgets.QLabel(title)
        t.setProperty('class', 'card-title')
        v = QtWidgets.QLabel(value)
        v.setProperty('class', 'card-value')
        layout.addWidget(t)
        layout.addWidget(v)
        layout.setSpacing(4)
        layout.setContentsMargins(12,8,12,8)
        self.value_label = v

    def set_value(self, text: str):
        self.value_label.setText(text)

# --- BasePage ---
class BasePage(QtWidgets.QWidget):
    def __init__(self, title: str):
        super().__init__()
        self.layout = QtWidgets.QVBoxLayout(self)
        self.layout.setContentsMargins(16, 16, 16, 16)
        self.title = QtWidgets.QLabel(title)
        self.title.setObjectName('PageTitle')
        self.layout.addWidget(self.title)

    def get_layout(self):
        return self.layout

# --- 1. InfoDashboardPage ---
class InfoDashboardPage(BasePage):
    def __init__(self, signals: GUISignals):
        super().__init__('Network Information Dashboard')
        self.signals = signals
        
        # --- Summary Cards ---
        card_layout = QtWidgets.QHBoxLayout()
        self.card_ip = SummaryCard('Local IP', 'N/A')
        self.card_gw = SummaryCard('Gateway', 'N/A')
        self.card_public_ip = SummaryCard('Public IP', 'N/A')
        self.card_status = SummaryCard('Status', 'N/A')
        for card in [self.card_ip, self.card_gw, self.card_public_ip, self.card_status]:
            card_layout.addWidget(card)
        self.get_layout().addLayout(card_layout)

        # --- GroupBox Layout ---
        main_layout = QtWidgets.QHBoxLayout()
        
        iface_group = QtWidgets.QGroupBox("Interface Details")
        info_layout = QtWidgets.QFormLayout()
        info_layout.addRow("IP Address:", QtWidgets.QLabel("N/A"))
        info_layout.addRow("Subnet Mask:", QtWidgets.QLabel("N/A"))
        info_layout.addRow("Gateway:", QtWidgets.QLabel("N/A"))
        info_layout.addRow("MAC Address:", QtWidgets.QLabel("N/A"))
        iface_group.setLayout(info_layout)
        main_layout.addWidget(iface_group)
        
        other_group = QtWidgets.QGroupBox("System & DNS")
        other_layout = QtWidgets.QFormLayout()
        other_layout.addRow("Hostname:", QtWidgets.QLabel("N/A"))
        other_layout.addRow("Primary DNS:", QtWidgets.QLabel("N/A"))
        other_layout.addRow("Secondary DNS:", QtWidgets.QLabel("N/A"))
        other_layout.addRow("Public IP:", QtWidgets.QLabel("N/A"))
        other_group.setLayout(other_layout)
        main_layout.addWidget(other_group)
        
        self.get_layout().addLayout(main_layout)
        self.get_layout().addStretch()
        
    def update_info(self, info: dict):
        """Public method to update all info fields."""
        self.card_ip.set_value(info.get('ip', 'N/A'))
        self.card_gw.set_value(info.get('gateway', 'N/A'))
        self.card_public_ip.set_value(info.get('public_ip', 'N/A'))
        self.card_status.set_value(info.get('status', 'N/A'))
        # ... etc ...

# --- 2. DevicesPage ---
class DevicesPage(BasePage):
    def __init__(self, signals: GUISignals):
        super().__init__('LAN Device Scanner')
        self.signals = signals

        # --- Top controls with summary cards ---
        top_row = QtWidgets.QHBoxLayout()
        left_controls = QtWidgets.QHBoxLayout()
        left_controls.addWidget(QtWidgets.QLabel('Interface:'))
        self.iface_combo = QtWidgets.QComboBox()
        self.iface_combo.addItems(['eth0','wlan0','All']) # TODO: Populate dynamically
        left_controls.addWidget(self.iface_combo)
        self.scan_btn = QtWidgets.QPushButton('Start ARP Scan')
        left_controls.addWidget(self.scan_btn)
        self.stop_btn = QtWidgets.QPushButton('Stop')
        self.stop_btn.setEnabled(False)
        left_controls.addWidget(self.stop_btn)
        left_controls.addStretch()

        self.card_count = SummaryCard('Devices Found', '0')
        self.card_last = SummaryCard('Last Seen', 'N/A')
        top_row.addLayout(left_controls, 2)
        top_row.addWidget(self.card_count, 1)
        top_row.addWidget(self.card_last, 1)
        self.get_layout().addLayout(top_row)

        # --- table + details in splitter ---
        split = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        
        self.table = QtWidgets.QTableWidget(0,5)
        self.table.setHorizontalHeaderLabels(['IP','MAC','Vendor','Hostname','Last Seen'])
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QtWidgets.QHeaderView.Interactive)
        self.table.setSortingEnabled(True)
        split.addWidget(self.table)

        detail_frame = QtWidgets.QFrame()
        dv_layout = QtWidgets.QVBoxLayout(detail_frame)
        self.details_box = QtWidgets.QGroupBox('Device Details & Actions')
        form = QtWidgets.QFormLayout()
        self.lbl_ip = QtWidgets.QLabel('---')
        self.lbl_mac = QtWidgets.QLabel('---')
        self.lbl_vendor = QtWidgets.QLabel('---')
        self.lbl_hostname = QtWidgets.QLabel('---')
        form.addRow('IP:', self.lbl_ip)
        form.addRow('MAC:', self.lbl_mac)
        form.addRow('Vendor:', self.lbl_vendor)
        form.addRow('Hostname:', self.lbl_hostname)
        self.details_box.setLayout(form)
        dv_layout.addWidget(self.details_box)

        actions = QtWidgets.QHBoxLayout()
        self.port_scan_btn = QtWidgets.QPushButton('Scan Ports')
        self.export_btn = QtWidgets.QPushButton('Export CSV')
        actions.addWidget(self.port_scan_btn)
        actions.addWidget(self.export_btn)
        dv_layout.addLayout(actions)
        dv_layout.addStretch()
        split.addWidget(detail_frame)
        split.setSizes([800, 300])
        self.get_layout().addWidget(split)
        
        # --- Collapsible advanced panel ---
        self.adv_panel = QtWidgets.QGroupBox('Advanced Scan Options')
        self.adv_panel.setCheckable(True)
        self.adv_panel.setChecked(False)
        adv_layout = QtWidgets.QFormLayout()
        adv_layout.addRow("Scan Range:", QtWidgets.QLineEdit("192.168.1.1/24"))
        adv_layout.addRow("Scan Type:", QtWidgets.QComboBox()) # TODO: Populate
        adv_layout.addRow(QtWidgets.QCheckBox("Use Nmap (if available)"))
        self.adv_panel.setLayout(adv_layout)
        self.get_layout().addWidget(self.adv_panel)

        # --- Connections ---
        self.scan_btn.clicked.connect(self._start_scan)
        self.stop_btn.clicked.connect(self._stop_scan)
        self.table.itemSelectionChanged.connect(self._select)
        self.port_scan_btn.clicked.connect(self._quick_port_scan)
        
    def _start_scan(self):
        iface = self.iface_combo.currentText()
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.table.setRowCount(0)
        self.card_count.set_value('0')
        self.card_last.set_value('N/A')
        
        
        self.signals.log.emit('info', f'ARP scan started on {iface}...')
        

    def _stop_scan(self):
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
      
        self.signals.log.emit('warn', 'ARP scan stopped by user.')

    def add_device(self, dev: dict):
        """Public method for worker to add/update device row."""
      
        r = self.table.rowCount()
        self.table.insertRow(r)
        self.table.setItem(r,0, QtWidgets.QTableWidgetItem(dev['ip']))
        self.table.setItem(r,1, QtWidgets.QTableWidgetItem(dev['mac']))
        self.table.setItem(r,2, QtWidgets.QTableWidgetItem(dev['vendor']))
        self.table.setItem(r,3, QtWidgets.QTableWidgetItem(dev['hostname']))
        self.table.setItem(r,4, QtWidgets.QTableWidgetItem(dev['seen']))
        
        self.card_count.set_value(str(self.table.rowCount()))
        self.card_last.set_value(dev['seen'])

    def scan_finished(self):
        """Public method for worker to call when finished."""
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.signals.log.emit('success', f'ARP scan finished. Found {self.table.rowCount()} devices.')

    def _select(self):
        sel = self.table.selectedItems()
        if not sel: return
        row = sel[0].row()
        self.lbl_ip.setText(self.table.item(row,0).text())
        self.lbl_mac.setText(self.table.item(row,1).text())
        self.lbl_vendor.setText(self.table.item(row,2).text())
        self.lbl_hostname.setText(self.table.item(row,3).text())

    def _quick_port_scan(self):
        if self.lbl_ip.text() == '---':
            self.signals.log.emit('error', 'No device selected to scan.')
            return
        
        target_ip = self.lbl_ip.text()
        self.signals.log.emit('info', f'Port scan requested for {target_ip}...')
        
        self.signals.start_port_scan.emit(target_ip, "22,80,443")

# --- 3. PortsPage ---
class PortsPage(BasePage):
    def __init__(self, signals: GUISignals):
        super().__init__("Port Scanner")
        self.signals = signals
        self.open_ports = 0
        
        # --- Controls ---
        ctrl_layout = QtWidgets.QHBoxLayout()
        ctrl_layout.addWidget(QtWidgets.QLabel("Target IP:"))
        self.target_ip = QtWidgets.QLineEdit()
        self.target_ip.setPlaceholderText("e.g., 192.168.1.1")
        ctrl_layout.addWidget(self.target_ip)
        ctrl_layout.addWidget(QtWidgets.QLabel("Ports (csv):"))
        self.ports = QtWidgets.QLineEdit("21,22,53,80,443,8080")
        ctrl_layout.addWidget(self.ports)
        self.scan_btn = QtWidgets.QPushButton("Scan Ports")
        ctrl_layout.addWidget(self.scan_btn)
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
        self.table = QtWidgets.QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Host", "Port", "Status", "Service/Banner"])
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.get_layout().addWidget(self.table)

        self.scan_btn.clicked.connect(self._start_scan)

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
        self.signals.log.emit('info', f"Starting port scan on {target}...")

        

    def add_result(self, res: dict):
        """Public method for worker to add a port result."""
        r = self.table.rowCount()
        self.table.insertRow(r)
        self.table.setItem(r, 0, QtWidgets.QTableWidgetItem(res['host']))
        self.table.setItem(r, 1, QtWidgets.QTableWidgetItem(str(res['port'])))
        item = QtWidgets.QTableWidgetItem(res['status'])
        if res['status'] == 'Open':
            item.setForeground(QtGui.QColor("#00FF00")) # Green
            self.open_ports += 1
            self.card_open.set_value(str(self.open_ports))
        self.table.setItem(r, 2, item)
        self.table.setItem(r, 3, QtWidgets.QTableWidgetItem(res['banner']))
        self.table.scrollToBottom()

    def scan_finished(self):
        """Public method for worker to call when finished."""
        self.card_status.set_value("Finished")
        self.scan_btn.setEnabled(True)
        self.signals.log.emit('success', f"Port scan on {self.target_ip.text()} finished.")
        
    def set_target(self, ip: str, ports: str):
        """Public method to pre-fill scan details from another page."""
        self.target_ip.setText(ip)
        self.ports.setText(ports)

# --- 4. TrafficPage (Packet Sniffer) ---
class TrafficPage(BasePage):
    def __init__(self, signals: GUISignals):
        super().__init__("Packet Sniffer (Live Traffic)")
        self.signals = signals
        self._counts = {'TCP':0,'UDP':0,'ICMP':0, 'DNS': 0, 'ARP': 0, 'Other':0}

        # --- Controls ---
        ctrl_layout = QtWidgets.QHBoxLayout()
        ctrl_layout.addWidget(QtWidgets.QLabel("Interface:"))
        self.iface = QtWidgets.QLineEdit("eth0") 
        self.iface.setFixedWidth(100)
        ctrl_layout.addWidget(self.iface)
        ctrl_layout.addWidget(QtWidgets.QLabel("BPF Filter:"))
        self.bpf = QtWidgets.QLineEdit("")
        self.bpf.setPlaceholderText("e.g., tcp or udp")
        ctrl_layout.addWidget(self.bpf)
        self.start_btn = QtWidgets.QPushButton("Start Capture")
        self.stop_btn = QtWidgets.QPushButton("Stop Capture")
        self.stop_btn.setEnabled(False)
        ctrl_layout.addWidget(self.start_btn)
        ctrl_layout.addWidget(self.stop_btn)
        self.get_layout().addLayout(ctrl_layout)
        
        # --- Protocol Stats ---
        stats_layout = QtWidgets.QHBoxLayout()
        self.proto_tcp = QtWidgets.QProgressBar(); self.proto_tcp.setFormat('TCP: %v')
        self.proto_udp = QtWidgets.QProgressBar(); self.proto_udp.setFormat('UDP: %v')
        self.proto_icmp = QtWidgets.QProgressBar(); self.proto_icmp.setFormat('ICMP: %v')
        self.proto_other = QtWidgets.QProgressBar(); self.proto_other.setFormat('Other: %v')
        self.progress_bars = [self.proto_tcp, self.proto_udp, self.proto_icmp, self.proto_other]
        for w in self.progress_bars:
            w.setRange(0, 100); w.setValue(0); w.setTextVisible(True); w.setFixedHeight(22)
            stats_layout.addWidget(w)
        self.get_layout().addLayout(stats_layout)

        # --- Main Splitter  ---
        main_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        
        self.table = QtWidgets.QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["No", "Time", "Source", "Destination", "Protocol", "Info"])
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QtWidgets.QHeaderView.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(5, QtWidgets.QHeaderView.Interactive)
        self.table.setColumnWidth(0, 70)
        self.table.setColumnWidth(5, 300)
        main_splitter.addWidget(self.table)
        
        bottom_splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        
        details_group = QtWidgets.QGroupBox("Packet Details")
        details_layout = QtWidgets.QVBoxLayout()
        self.details_tree = QtWidgets.QTreeWidget()
        self.details_tree.setHeaderHidden(True)
        self.details_tree.addTopLevelItem(QtWidgets.QTreeWidgetItem(["Select a packet to see details..."]))
        details_layout.addWidget(self.details_tree)
        details_group.setLayout(details_layout)
        bottom_splitter.addWidget(details_group)
        
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

        self.start_btn.clicked.connect(self._start)
        self.stop_btn.clicked.connect(self._stop)
        self.table.itemSelectionChanged.connect(self._select_packet)

    def _start(self):
        iface = self.iface.text().strip()
        bpf = self.bpf.text().strip()
        
        self.table.setRowCount(0)
        self._counts = {k: 0 for k in self._counts}
        for pb in self.progress_bars:
            pb.setValue(0)
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.signals.log.emit('info', f"Capture started on {iface}...")
        
        

    def _stop(self):
        """Called by the Stop button."""
        self.signals.log.emit('warn', "Capture stop requested by user.")
      
        self.stop_capture_finished() 

    def stop_capture_finished(self):
        """Public method for worker to call when capture has fully stopped."""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.signals.log.emit('success', "Capture finished.")

    def add_packet_row(self, pkt: dict):
        """Public method for worker to add a packet."""
        r = self.table.rowCount()
        self.table.insertRow(r)
        self.table.setItem(r,0, QtWidgets.QTableWidgetItem(str(pkt['no'])))
        self.table.setItem(r,1, QtWidgets.QTableWidgetItem(pkt['time']))
        self.table.setItem(r,2, QtWidgets.QTableWidgetItem(pkt['src']))
        self.table.setItem(r,3, QtWidgets.QTableWidgetItem(pkt['dst']))
        self.table.setItem(r,4, QtWidgets.QTableWidgetItem(pkt['proto']))
        self.table.setItem(r,5, QtWidgets.QTableWidgetItem(pkt['info']))
        
        if r > 800: self.table.removeRow(0)
        if r % 10 == 0: self.table.scrollToBottom()

        # Update protocol stats
        proto = pkt['proto']
        if proto in self._counts:
            self._counts[proto] += 1
        else:
            self._counts['Other'] += 1
        
        total = sum(self._counts.values()) or 1
       .
        self.proto_tcp.setValue(int(self._counts['TCP'] / total * 100))
        self.proto_udp.setValue(int(self._counts['UDP'] / total * 100))
        self.proto_icmp.setValue(int(self._counts['ICMP'] / total * 100))
        self.proto_other.setValue(int(self._counts['Other'] / total * 100))
        self.proto_tcp.setFormat(f"TCP: {self._counts['TCP']}")
        self.proto_udp.setFormat(f"UDP: {self._counts['UDP']}")
        self.proto_icmp.setFormat(f"ICMP: {self._counts['ICMP']}")
        self.proto_other.setFormat(f"Other: {self._counts['Other']}")

    def _select_packet(self):
      
        self.details_tree.clear()
        self.details_tree.addTopLevelItem(QtWidgets.QTreeWidgetItem(["Packet details..."]))
        self.bytes_text.setText("Packet bytes...")


# --- 5. PcapImportPage ---
class PcapImportPage(BasePage):
    def __init__(self, signals: GUISignals):
        super().__init__("PCAP Import & Analyzer")
        self.signals = signals
        
        # --- Controls ---
        ctrl_layout = QtWidgets.QHBoxLayout()
        self.open_btn = QtWidgets.QPushButton("Open .pcap File")
        ctrl_layout.addWidget(self.open_btn)
        self.file_label = QtWidgets.QLabel("No file loaded.")
        ctrl_layout.addWidget(self.file_label)
        ctrl_layout.addStretch()
        self.export_btn = QtWidgets.QPushButton("Export to CSV") # Added export
        ctrl_layout.addWidget(self.export_btn)
        self.get_layout().addLayout(ctrl_layout)
        
        # --- Main Vertical Splitter (like Wireshark) ---
        main_splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        
        self.table = QtWidgets.QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["No", "Time", "Source", "Destination", "Protocol", "Info"])
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QtWidgets.QHeaderView.Interactive)
        self.table.setColumnWidth(0, 70)
        main_splitter.addWidget(self.table)
        
        bottom_splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        
        details_group = QtWidgets.QGroupBox("Packet Details")
        details_layout = QtWidgets.QVBoxLayout()
        self.details_tree = QtWidgets.QTreeWidget()
        self.details_tree.setHeaderHidden(True)
        self.details_tree.addTopLevelItem(QtWidgets.QTreeWidgetItem(["Load a PCAP and select a packet..."]))
        details_layout.addWidget(self.details_tree)
        details_group.setLayout(details_layout)
        bottom_splitter.addWidget(details_group)
        
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
        
        self.open_btn.clicked.connect(self._open_file)
        self.export_btn.clicked.connect(self._export)

    def _open_file(self):
       
        
        self.signals.log.emit('info', "Open file clicked (no logic).")
        self.file_label.setText("dummy.pcap (not loaded)")


    def _export(self):
       
        self.signals.log.emit('info', "Export to CSV clicked (no logic).")

# --- 6. StatsPage ---
class StatsPage(BasePage):
    def __init__(self, signals: GUISignals):
        super().__init__("Real-Time Network Statistics")
        self.signals = signals

        # --- Summary Cards ---
        card_layout = QtWidgets.QHBoxLayout()
        self.card_in = SummaryCard("Bandwidth In", "0 Kbps")
        self.card_out = SummaryCard("Bandwidth Out", "0 Kbps")
        self.card_total = SummaryCard("Total Data", "0 MB")
        card_layout.addWidget(self.card_in)
        card_layout.addWidget(self.card_out)
        card_layout.addWidget(self.card_total)
        self.get_layout().addLayout(card_layout)

        # --- Graph and Top Talkers ---
        main_layout = QtWidgets.QHBoxLayout()
        
        graph_group = QtWidgets.QGroupBox("Live Bandwidth")
        graph_layout = QtWidgets.QVBoxLayout()
        self.graph_placeholder = QtWidgets.QFrame()
        self.graph_placeholder.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.graph_placeholder.setMinimumHeight(300)
        graph_layout.addWidget(self.graph_placeholder)
        graph_group.setLayout(graph_layout)
        main_layout.addWidget(graph_group, 2)
        
        talkers_group = QtWidgets.QGroupBox("Top Talkers")
        talkers_layout = QtWidgets.QVBoxLayout()
        self.talkers_table = QtWidgets.QTableWidget(0, 2)
        self.talkers_table.setHorizontalHeaderLabels(["Source IP", "Data Sent"])
        self.talkers_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        talkers_layout.addWidget(self.talkers_table)
        talkers_group.setLayout(talkers_layout)
        main_layout.addWidget(talkers_group, 1)
        
        self.get_layout().addLayout(main_layout)

        

    def update_stats(self, bw_in, bw_out, total_data, talkers):
        """Public method for worker to update stats."""
        self.card_in.set_value(f"{bw_in} Kbps")
        self.card_out.set_value(f"{bw_out} Kbps")
        self.card_total.set_value(f"{total_data:.2f} MB")
        
        self.talkers_table.setRowCount(0)
        self.talkers_table.setSortingEnabled(False)
        for ip, data in talkers.items():
            r = self.talkers_table.rowCount()
            self.talkers_table.insertRow(r)
            self.talkers_table.setItem(r, 0, QtWidgets.QTableWidgetItem(ip))
            self.talkers_table.setItem(r, 1, QtWidgets.QTableWidgetItem(f"{data / 1024.0:.2f} MB"))
        self.talkers_table.setSortingEnabled(True)

# --- 7. SpeedTestPage ---
class SpeedTestPage(BasePage):
    def __init__(self, signals: GUISignals):
        super().__init__("Network Speed Test")
        self.signals = signals
        
        # --- Controls ---
        ctrl_layout = QtWidgets.QHBoxLayout()
        self.run_btn = QtWidgets.QPushButton("Run Speed Test")
        self.run_btn.setMinimumHeight(40)
        ctrl_layout.addWidget(self.run_btn)
        self.status_label = QtWidgets.QLabel("Click 'Run Speed Test' to begin.")
        self.status_label.setStyleSheet("font-style: italic; color: #999;")
        ctrl_layout.addWidget(self.status_label)
        ctrl_layout.addStretch()
        self.get_layout().addLayout(ctrl_layout)
        
        # --- Results Display (Cards) ---
        card_layout = QtWidgets.QHBoxLayout()
        self.card_ping = SummaryCard("Ping", "--- ms")
        self.card_down = SummaryCard("Download", "--- Mbps")
        self.card_up = SummaryCard("Upload", "--- Mbps")
        card_layout.addWidget(self.card_ping)
        card_layout.addWidget(self.card_down)
        card_layout.addWidget(self.card_up)
        self.get_layout().addLayout(card_layout)

        # --- Progress "Gauges" (QProgressBar) ---
        progress_layout = QtWidgets.QFormLayout()
        self.down_progress = QtWidgets.QProgressBar()
        self.down_progress.setRange(0, 100); self.down_progress.setValue(0)
        self.up_progress = QtWidgets.QProgressBar()
        self.up_progress.setRange(0, 100); self.up_progress.setValue(0)
        progress_layout.addRow("Download:", self.down_progress)
        progress_layout.addRow("Upload:", self.up_progress)
        self.get_layout().addLayout(progress_layout)
        
        self.get_layout().addStretch()
        
        self.run_btn.clicked.connect(self._run)

    def _run(self):
        self.signals.log.emit('info', "Starting speed test...")
        self.run_btn.setEnabled(False)
        self.status_label.setText("Testing... (connect worker)")
        
    

    def update_progress(self, test_type: str, value: float, current_speed: float = 0):
        """Public method for worker to update progress."""
        if test_type == 'ping':
            self.card_ping.set_value(f"{value:.2f} ms")
        elif test_type == 'download':
            self.down_progress.setValue(int(value)) 
            self.card_down.set_value(f"{current_speed:.2f} Mbps")
        elif test_type == 'upload':
            self.up_progress.setValue(int(value))
            self.card_up.set_value(f"{current_speed:.2f} Mbps")
            
    def test_finished(self, results: dict):
        """Public method for worker to call when done."""
        self.status_label.setText("Test finished.")
        self.run_btn.setEnabled(True)
        self.card_ping.set_value(f"{results.get('ping', 0):.2f} ms")
        self.card_down.set_value(f"{results.get('download', 0):.2f} Mbps")
        self.card_up.set_value(f"{results.get('upload', 0):.2f} Mbps")
        self.down_progress.setValue(100)
        self.up_progress.setValue(100)
        self.signals.log.emit('success', "Speed test complete.")


# --- 8. DNSLookupPage ---
class DNSLookupPage(BasePage):
    def __init__(self, signals: GUISignals):
        super().__init__("DNS Lookup")
        self.signals = signals
        
        ctrl_layout = QtWidgets.QHBoxLayout()
        ctrl_layout.addWidget(QtWidgets.QLabel("Domain:"))
        self.domain_input = QtWidgets.QLineEdit("google.com")
        ctrl_layout.addWidget(self.domain_input)
        self.record_type = QtWidgets.QComboBox()
        self.record_type.addItems(["A", "AAAA", "MX", "NS", "TXT"])
        ctrl_layout.addWidget(self.record_type)
        self.lookup_btn = QtWidgets.QPushButton("Lookup")
        ctrl_layout.addWidget(self.lookup_btn)
        ctrl_layout.addStretch()
        self.get_layout().addLayout(ctrl_layout)
        
        self.results_text = QtWidgets.QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setPlaceholderText("DNS query results will appear here...")
        self.get_layout().addWidget(self.results_text)
        
        self.lookup_btn.clicked.connect(self._run_lookup)

    def _run_lookup(self):
        domain = self.domain_input.text()
        rectype = self.record_type.currentText()
        self.signals.log.emit('info', f"Running DNS lookup for {domain} ({rectype})...")
        
  
        self.results_text.setText(f";; Querying {domain} for {rectype}...")
        
    def show_results(self, text: str):
        """Public method for worker to show results."""
        self.results_text.setText(text)

# --- 9. RouterAdminPage ---
class RouterAdminPage(BasePage):
    def __init__(self, signals: GUISignals):
        super().__init__("Router Admin Access")
        self.signals = signals
        
        card_layout = QtWidgets.QHBoxLayout()
        self.card_gw = SummaryCard("Gateway IP", "N/A")
        self.card_model = SummaryCard("Router Model", "N/A")
        card_layout.addWidget(self.card_gw)
        card_layout.addWidget(self.card_model)
        self.get_layout().addLayout(card_layout)

        info_layout = QtWidgets.QVBoxLayout()
        self.open_btn = QtWidgets.QPushButton("Open Admin Page in Browser")
        self.open_btn.setMinimumHeight(40)
        info_layout.addWidget(self.open_btn)
        info_layout.addStretch()
        self.get_layout().addLayout(info_layout)
        
        self.open_btn.clicked.connect(self._open_gateway)
        
    def _open_gateway(self):
      
        gateway_ip = self.card_gw.value_label.text()
        if gateway_ip == 'N/A':
            self.signals.log.emit('error', "Gateway IP not found.")
            return
        self.signals.log.emit('info', f"Opening http://{gateway_ip} in browser...")
       
        
    def set_info(self, ip: str, model: str):
        """Public method to update router info."""
        self.card_gw.set_value(ip)
        self.card_model.set_value(model)

# --- 10. UptimePage ---
class UptimePage(BasePage):
    def __init__(self, signals: GUISignals):
        super().__init__("Connection Uptime")
        self.signals = signals
        
        card_layout = QtWidgets.QHBoxLayout()
        self.card_iface = SummaryCard("Interface", "N/A")
        self.card_status = SummaryCard("Status", "Unknown")
        self.card_start = SummaryCard("Connected Since", "N/A")
        self.card_uptime = SummaryCard("Uptime", "0s")
        card_layout.addWidget(self.card_iface)
        card_layout.addWidget(self.card_status)
        card_layout.addWidget(self.card_start)
        card_layout.addWidget(self.card_uptime)
        self.get_layout().addLayout(card_layout)
        
        self.get_layout().addStretch()

    def update_uptime(self, app_start_time):
        """This will be called by the main window timer."""
        uptime_s = int(time.time() - app_start_time)
        m, s = divmod(uptime_s, 60)
        h, m = divmod(m, 60)
        d, h = divmod(h, 24)
        self.card_uptime.set_value(f"{d}d {h}h {m}m {s}s")
        


# --- 11. WifiScannerPage ---
class WifiScannerPage(BasePage):
    def __init__(self, signals: GUISignals):
        super().__init__("Surrounding Wi-Fi Scanner")
        self.signals = signals

        top_layout = QtWidgets.QHBoxLayout()
        self.scan_btn = QtWidgets.QPushButton("Scan for Networks")
        top_layout.addWidget(self.scan_btn)
        top_layout.addStretch()
        self.card_found = SummaryCard("Networks Found", "0")
        self.card_best = SummaryCard("Best Signal", "--- dBm")
        top_layout.addWidget(self.card_found)
        top_layout.addWidget(self.card_best)
        self.get_layout().addLayout(top_layout)
        
        self.table = QtWidgets.QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["SSID", "BSSID", "Signal (dBm)", "Channel", "Frequency", "Encryption"])
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.setSortingEnabled(True)
        self.get_layout().addWidget(self.table)
        
        self.warning_label = QtWidgets.QLabel("Real scan requires a compatible Wi-Fi adapter and root privileges.")
        self.warning_label.setStyleSheet("color: #FFA500; font-weight: bold;") # Warn color
        self.get_layout().addWidget(self.warning_label)
        
        self.scan_btn.clicked.connect(self._start_scan)

    def _start_scan(self):
        self.scan_btn.setEnabled(False)
        self.table.setRowCount(0)
        self.card_found.set_value("0")
        self.card_best.set_value("--- dBm")
        
        
        self.signals.log.emit('info', "Starting Wi-Fi scan...")
        

    def add_network(self, net: dict, best_signal: int):
        """Public method for worker to add a network."""
        self.card_found.set_value(str(self.table.rowCount() + 1))
        self.card_best.set_value(f"{best_signal} dBm")
            
        r = self.table.rowCount()
        self.table.insertRow(r)
        self.table.setItem(r, 0, QtWidgets.QTableWidgetItem(net['ssid']))
        self.table.setItem(r, 1, QtWidgets.QTableWidgetItem(net['bssid']))
        self.table.setItem(r, 2, QtWidgets.QTableWidgetItem(str(net['signal'])))
        self.table.setItem(r, 3, QtWidgets.QTableWidgetItem(str(net['channel'])))
        self.table.setItem(r, 4, QtWidgets.QTableWidgetItem(net['freq']))
        self.table.setItem(r, 5, QtWidgets.QTableWidgetItem(net['enc']))

    def scan_finished(self):
        """Public method for worker to call when finished."""
        self.scan_btn.setEnabled(True)
        self.signals.log.emit('success', f"Wi-Fi scan finished. Found {self.table.rowCount()} networks.")


# --- MainWindow ---
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WiFi Manager - Network Toolkit (Scaffold)")
        self.resize(1366, 800)
        self.setWindowIcon(self.style().standardIcon(QtWidgets.QStyle.SP_ComputerIcon))
        
        self.signals = GUISignals()
        self.packet_counter = 0 # This will be updated by the sniffer worker
        self.start_time = time.time()
        
        self._build_ui()
        self._setup_global_timer()
        
        self.signals.log.emit('info', "Application initialized. Ready.")

    def _build_ui(self):
        # --- ToolBar ---
        tb = self.addToolBar("Quick Actions")
        tb.setToolButtonStyle(QtCore.Qt.ToolButtonTextBesideIcon)
        self.action_scan = tb.addAction(self.style().standardIcon(QtWidgets.QStyle.SP_DriveNetIcon), "Scan Devices")
        self.action_sniff = tb.addAction(self.style().standardIcon(QtWidgets.QStyle.SP_FileDialogListView), "Start Capture")
        
        self.action_open_console = tb.addAction(self.style().standardIcon(QtWidgets.QStyle.SP_DirOpenIcon), "Open New Console")
        self.action_open_console.setEnabled(False) # Start disabled (log is visible)
        
        # --- Central Widget (Nav + Stack) ---
        central = QtWidgets.QWidget()
        h = QtWidgets.QHBoxLayout(central)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        
        self.nav = QtWidgets.QListWidget()
        self.nav.setFixedWidth(220)
        h.addWidget(self.nav)
        
        self.stack = QtWidgets.QStackedWidget()
        h.addWidget(self.stack)
        self.setCentralWidget(central)

        # --- Dock Log ---
        self.log_dock = QtWidgets.QDockWidget('Master Event Log', self)
        self.log_widget = QtWidgets.QTextEdit()
        self.log_widget.setReadOnly(True)
        self.log_widget.setObjectName("GlobalLog")
        self.log_dock.setWidget(self.log_widget)
        self.log_dock.setFeatures(QtWidgets.QDockWidget.DockWidgetClosable | QtWidgets.QDockWidget.DockWidgetFloatable) 
        self.addDockWidget(QtCore.Qt.BottomDockWidgetArea, self.log_dock)

        # --- Status Bar ---
        self.status_bar = self.statusBar()
        self.status_uptime = QtWidgets.QLabel("Uptime: 0s")
        self.status_packets = QtWidgets.QLabel("Packets: 0")
        self.status_bar.addPermanentWidget(self.status_uptime)
        self.status_bar.addPermanentWidget(self.status_packets)

        # --- Create and Add All 11 Pages ---
        self._setup_nav()
        
        # --- Connect Signals ---
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.signals.log.connect(self._append_log)
        self.log_dock.visibilityChanged.connect(self._on_log_visibility_changed)
        
        # Connect quick-port-scan signal
        self.signals.start_port_scan.connect(self._go_to_port_scan)
        
        # Toolbar connections
        self.action_scan.triggered.connect(lambda: self._activate_page('LAN Devices') and self.devices_page.scan_btn.click())
        self.action_sniff.triggered.connect(lambda: self._activate_page('Packet Sniffer') and self.traffic_page.start_btn.click())
        self.action_open_console.triggered.connect(self.log_dock.show)
        
        self.nav.setCurrentRow(0)

    def _setup_nav(self):
        """Creates all 11 pages and adds them to nav/stack."""
        style = self.style()
        
        self.info_page = InfoDashboardPage(self.signals)
        self._add_nav_item("Network Info", style.standardIcon(QtWidgets.QStyle.SP_ComputerIcon), self.info_page)
        
        self.devices_page = DevicesPage(self.signals)
        self._add_nav_item("LAN Devices", style.standardIcon(QtWidgets.QStyle.SP_DriveNetIcon), self.devices_page)
        
        self.ports_page = PortsPage(self.signals)
        self._add_nav_item("Port Scanner", style.standardIcon(QtWidgets.QStyle.SP_FileDialogDetailedView), self.ports_page)
        
        self.traffic_page = TrafficPage(self.signals)
        self._add_nav_item("Packet Sniffer", style.standardIcon(QtWidgets.QStyle.SP_FileDialogListView), self.traffic_page)
        
        self.pcap_page = PcapImportPage(self.signals)
        self._add_nav_item("PCAP Analyzer", style.standardIcon(QtWidgets.QStyle.SP_FileIcon), self.pcap_page)
        
        self.stats_page = StatsPage(self.signals)
        self._add_nav_item("Network Stats", style.standardIcon(QtWidgets.QStyle.SP_ArrowUp), self.stats_page)
        
        self.speed_page = SpeedTestPage(self.signals)
        self._add_nav_item("Speed Test", style.standardIcon(QtWidgets.QStyle.SP_MediaSeekForward), self.speed_page)

        self.dns_page = DNSLookupPage(self.signals)
        self._add_nav_item("DNS Lookup", style.standardIcon(QtWidgets.QStyle.SP_DialogHelpButton), self.dns_page)
        
        self.router_page = RouterAdminPage(self.signals)
        self._add_nav_item("Router Admin", style.standardIcon(QtWidgets.QStyle.SP_DirHomeIcon), self.router_page)
        
        self.uptime_page = UptimePage(self.signals)
        self._add_nav_item("Uptime Tracker", style.standardIcon(QtWidgets.QStyle.SP_BrowserReload), self.uptime_page)
        
        self.wifi_page = WifiScannerPage(self.signals)
        self._add_nav_item("Wi-Fi Scanner", style.standardIcon(QtWidgets.QStyle.SP_FileDialogInfoView), self.wifi_page)

    def _add_nav_item(self, text, icon, page_widget):
        item = QtWidgets.QListWidgetItem(icon, text)
        self.nav.addItem(item)
        self.stack.addWidget(page_widget)
        
    def _activate_page(self, name: str):
        """Finds and activates a page by its name."""
        for i in range(self.nav.count()):
            if self.nav.item(i).text() == name:
                self.nav.setCurrentRow(i)
                return True
        return False
        
    def _on_log_visibility_changed(self, visible):
        """Activates the 'Open New Console' button only when the log is closed."""
        self.action_open_console.setEnabled(not visible)

    def _setup_global_timer(self):
        """A master timer to make the GUI feel 'alive'."""
        self.timer = QTimer(self)
        self.timer.setInterval(1000) # Every 1 second
        self.timer.timeout.connect(self._update_live_widgets)
        self.timer.start()

    def _update_live_widgets(self):
        # Update Status Bar
        uptime_s = int(time.time() - self.start_time)
        self.status_uptime.setText(f"Uptime: {uptime_s}s")
        
        
        if uptime_s % 30 == 0:
            self.signals.log.emit('debug', "System poll...")
            
    def _go_to_port_scan(self, ip: str, ports: str):
        """Slot to jump to port scanner page."""
        self._activate_page("Port Scanner")
        self.ports_page.set_target(ip, ports)
        self.ports_page.scan_btn.click()

    def _append_log(self, level: str, text: str):
        ts = time.strftime('%H:%M:%S')
        
        # Color-code the log
        color_map = {
            'info': '#00BFFF',
            'success': '#00FF00',
            'warn': '#FFA500',
            'error': '#FF4500',
            'debug': '#888888'
        }
        color = color_map.get(level, '#e6f7ff')
        
        self.log_widget.append(f'<span style="color: {color};">[{ts}][{level.upper()}] {text}</span>')
        self.log_widget.verticalScrollBar().setValue(self.log_widget.verticalScrollBar().maximum())
        
        if level != 'debug':
            self.status_bar.showMessage(text, 4000) # Show in status bar

    def _stop_all_tasks(self):
        """Stops all running tasks."""
        self.signals.log.emit('warn', "STOP ALL tasks requested!")
       
        self.devices_page._stop_scan()
        self.traffic_page._stop()
       
        
    def closeEvent(self, event):
        self.signals.log.emit('info', "Shutting down...")
        self._stop_all_tasks()
        event.accept()

# --- Run ---
def run_app():
    app = QtWidgets.QApplication(sys.argv)
    app.setStyleSheet(CYBER_STYLESHEET)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    run_app()
