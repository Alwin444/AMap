"""
app/main_window.py
Integrates features including Traceroute, SSL, WHOIS.

"""
from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtCore import pyqtSignal, QTimer
import sys, time, subprocess

# --- Page Imports ---
from app.pages.info_dashboard import InfoDashboardPage
from app.pages.devices_page import DevicesPage
from app.pages.port_scan_page import PortsPage
from app.pages.traffic_page import TrafficPage
from app.pages.pcap_import_page import PcapImportPage
from app.pages.stats_page import StatsPage
from app.pages.speed_test_page import SpeedTestPage
from app.pages.wifi_scanner_page import WifiScannerPage
from app.pages.dns_lookup_page import DNSLookupPage
from app.pages.firewall_page import FirewallPage
from app.pages.traceroute_page import TraceroutePage
from app.pages.ssl_page import SSLPage
from app.pages.whois_page import WhoisPage

from app.pages.subdomain_page import SubdomainPage

# --- Backend Imports ---
from app.utils.network import get_local_ip, get_default_gateway, get_public_ip, get_interfaces, get_dns_servers, get_mac_address, get_arp_mac
from app.utils.oui import lookup_vendor
from app.workers.arp_scan import ArpScanWorker
from app.workers.capture_worker import CaptureWorker
from app.workers.port_scan_worker import PortScanWorker
from app.workers.ip_worker import PublicIpWorker
from app.workers.stats_worker import NetworkStatsWorker
from app.workers.speed_test_worker import SpeedTestWorker
from app.workers.wireless_scan import WifiScanWorker
from app.workers.firewall_worker import FirewallScanWorker
from app.workers.dns_worker import DNSLookupWorker
from app.workers.traceroute_worker import TracerouteWorker

from app.workers.ssl_worker import SSLWorker
from app.workers.whois_worker import WhoisWorker
from app.workers.subdomain_worker import SubdomainWorker

# --- Stylesheet  ---
CYBER_STYLESHEET = r"""
QWidget { background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #071028, stop:0.5 #0f2a3a, stop:1 #1b3b4d); color: #e6f7ff; font-family: 'Segoe UI', 'Arial'; font-size: 10pt; }
QMainWindow { background: transparent; }
QMenuBar { background-color: rgba(10,30,45,0.85); color: #e6f7ff; }
QMenuBar::item:selected { background: rgba(0,255,153,0.1); }
QMenu { background: #0f2a3a; border: 1px solid rgba(0,255,153,0.1); }
QMenu::item:selected { background: rgba(0,255,153,0.1); }
QStatusBar { background: rgba(10,30,45,0.9); color: #00ff99; font-weight: bold; }
QStatusBar::item { border: none; padding: 0 8px; }
QToolBar { background: rgba(10,30,45,0.85); border: none; }
QToolBar QToolButton { color: #e6f7ff; padding: 6px; font-weight: bold; }
QToolBar QToolButton:hover { background: rgba(0,255,153,0.1); }
QListWidget { background: rgba(10,30,45,0.85); border: none; font-size: 11pt; padding-top: 8px; icon-size: 20px; }
QListWidget::item { padding: 12px 18px; margin: 2px 6px; border-radius: 6px; }
QListWidget::item:hover { background: rgba(0,255,153,0.06); }
QListWidget::item:selected { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #002b2b, stop:1 #005f3f); color: #b9fff0; }
QLabel#PageTitle { font-weight: 700; font-size: 15pt; color: #00ff99; padding-bottom: 6px; }
QFrame.card { background: rgba(255,255,255,0.03); border: 1px solid rgba(0,255,153,0.08); border-radius: 8px; padding: 10px; }
QLabel.card-title { color: #bfffe1; font-weight: 600; font-size: 9pt; }
QLabel.card-value { color: #e6fff4; font-size: 14pt; font-weight: 700; }
QPushButton { background: rgba(0,255,153,0.10); color: #dfffe9; border: 1px solid rgba(0,255,153,0.12); padding: 8px 14px; border-radius: 6px; font-weight: bold; }
QPushButton:hover { background: rgba(0,255,153,0.14); }
QPushButton:pressed { background: rgba(0,255,153,0.08); }
QPushButton:disabled { background: rgba(255,255,255,0.02); color: #555; }
QLineEdit, QTextEdit { background: rgba(255,255,255,0.02); border: 1px solid rgba(0,255,153,0.06); padding: 6px; border-radius: 6px; color: #e6f7ff; }
QLineEdit:focus, QTextEdit:focus { border: 1px solid #00ff99; }
QComboBox { background: rgba(255,255,255,0.02); border: 1px solid rgba(0,255,153,0.06); padding: 6px; border-radius: 6px; }
QComboBox QAbstractItemView { background: #0f2a3a; color: #e6f7ff; selection-background-color: #005f3f; }
QTableWidget { background: rgba(255,255,255,0.02); border: 1px solid rgba(0,255,153,0.05); gridline-color: rgba(0,255,153,0.05); }
QHeaderView::section { background: rgba(0,255,153,0.03); color: #dfffe9; padding: 6px; border: none; font-weight: bold; }
QTreeWidget { background: rgba(255,255,255,0.02); border: 1px solid rgba(0,255,153,0.05); }
QTreeWidget::item:selected { background: #005f3f; color: #b9fff0; }
QGroupBox { border: 1px solid rgba(0,255,153,0.1); border-radius: 6px; margin-top: 10px; font-weight: bold; }
QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 0 5px; color: #00ff99; }
QGroupBox[checkable="true"]::indicator { padding: 4px; }
QSplitter::handle { background-color: rgba(0,255,153,0.05); height: 4px; width: 4px; }
QSplitter::handle:hover { background-color: #00ff99; }
QDockWidget { background: rgba(5,15,25,0.85); color: #e6f7ff; font-weight: bold; }
QDockWidget::title { background: #0f2a3a; padding: 6px; color: #00ff99; }
QTextEdit#GlobalLog { background: #050a12; color: #00ff99; font-family: 'Monospace', 'Courier New'; font-size: 9pt; border: 1px solid rgba(0,255,153,0.1); }
QProgressBar { border: 1px solid rgba(0,255,153,0.2); border-radius: 4px; text-align: center; color: #e6f7ff; background-color: rgba(255,255,255,0.02); }
QProgressBar::chunk { background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #005f3f, stop:1 #00ff99); border-radius: 4px; }
"""

class GUISignals(QtCore.QObject):
    start_arp_scan = pyqtSignal(str, str, bool)
    stop_arp_scan = pyqtSignal()
    start_capture = pyqtSignal(str, str)
    stop_capture = pyqtSignal()
    start_port_scan = pyqtSignal(str, str)
    stop_port_scan = pyqtSignal()
    start_speed_test = pyqtSignal()
    start_wifi_scan = pyqtSignal()
    log = pyqtSignal(str, str)

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WiFi Manager - Network Toolkit")
        self.resize(1366, 800)
        self.setWindowIcon(self.style().standardIcon(QtWidgets.QStyle.SP_ComputerIcon))
        
        self.signals = GUISignals()
        self.packet_counter = 0 
        self.start_time = time.time()
        self.is_web_mode = False
        
        # Worker references
        self.arp_worker = None
        self.capture_worker = None
        self.port_worker = None
        self.ip_worker = None
        self.stats_worker = None
        self.speed_worker = None 
        self.wifi_worker = None
        self.firewall_worker = None
        self.dns_worker = None
        self.traceroute_worker = None 
        
        self.ssl_worker = None 
        self.whois_worker = None 
        self.subdomain_worker = None
        
        self._init_pages()
        self._build_ui()
        self._setup_global_timer()
        self._connect_workers()
        self._load_initial_data()
        
        self.signals.log.emit('info', "Application initialized. Ready.")

    def _init_pages(self):
        # Initialize ALL pages once to keep state
        self.info_page = InfoDashboardPage(self.signals)
        self.devices_page = DevicesPage(self.signals)
        self.ports_page = PortsPage(self.signals)
        self.traffic_page = TrafficPage(self.signals) 
        self.pcap_page = PcapImportPage(self.signals)
        self.stats_page = StatsPage(self.signals)
        self.speed_page = SpeedTestPage(self.signals)
        self.wifi_page = WifiScannerPage(self.signals)
        
        # Web / Extra Pages
        self.dns_page = DNSLookupPage(self.signals)
        self.firewall_page = FirewallPage(self.signals)
        self.traceroute_page = TraceroutePage(self.signals)
        
        self.ssl_page = SSLPage(self.signals) 
        self.whois_page = WhoisPage(self.signals) 
        self.subdomain_page = SubdomainPage(self.signals) 
        
        # Connect page-specific signals
        self.firewall_page.start_scan.connect(self._handle_firewall_start)
        self.dns_page.start_lookup_signal.connect(self._handle_dns_start)
        self.traceroute_page.start_trace_signal.connect(self._handle_trace_start)
        self.ssl_page.start_scan.connect(self._handle_ssl_start)
        self.whois_page.start_lookup.connect(self._handle_whois_start)
        self.subdomain_page.start_scan_signal.connect(self._handle_subdomain_start)
        

    def _build_ui(self):
        self.toolbar = self.addToolBar("Quick Actions")
        self.toolbar.setToolButtonStyle(QtCore.Qt.ToolButtonTextBesideIcon)
        
        self.action_mode_switch = self.toolbar.addAction(
            self.style().standardIcon(QtWidgets.QStyle.SP_ComputerIcon), 
            "Web Play"
        )
        self.action_mode_switch.triggered.connect(self._toggle_mode)
        self.toolbar.addSeparator()
        
        self.action_open_console = self.toolbar.addAction(
            self.style().standardIcon(QtWidgets.QStyle.SP_DirOpenIcon), 
            "Open New Console"
        )
        self.action_open_console.setEnabled(False)
        self.action_open_console.triggered.connect(self.log_dock_show)
        
        central = QtWidgets.QWidget()
        h = QtWidgets.QHBoxLayout(central)
        h.setContentsMargins(0, 0, 0, 0)
        self.nav = QtWidgets.QListWidget()
        self.nav.setFixedWidth(220)
        self.nav.currentRowChanged.connect(self._on_nav_click)
        h.addWidget(self.nav)
        self.stack = QtWidgets.QStackedWidget()
        h.addWidget(self.stack)
        self.setCentralWidget(central)

        # Add pages to stack 
        for p in [self.info_page, self.devices_page, self.ports_page, self.traffic_page, 
                  self.pcap_page, self.stats_page, self.speed_page, self.wifi_page, 
                  self.dns_page, self.firewall_page, self.traceroute_page,
                  self.ssl_page, self.whois_page, self.subdomain_page]:
            self.stack.addWidget(p)

        self.log_dock = QtWidgets.QDockWidget('Master Event Log', self)
        self.log_widget = QtWidgets.QTextEdit(); self.log_widget.setReadOnly(True); self.log_widget.setObjectName("GlobalLog")
        self.log_dock.setWidget(self.log_widget)
        self.log_dock.setFeatures(QtWidgets.QDockWidget.DockWidgetClosable | QtWidgets.QDockWidget.DockWidgetFloatable) 
        self.addDockWidget(QtCore.Qt.BottomDockWidgetArea, self.log_dock)

        self.status_bar = self.statusBar()
        self.status_uptime = QtWidgets.QLabel("Uptime: 0s")
        self.status_packets = QtWidgets.QLabel("Packets: 0")
        self.status_bar.addPermanentWidget(self.status_uptime)
        self.status_bar.addPermanentWidget(self.status_packets)
        self._setup_network_nav()

    def log_dock_show(self): self.log_dock.show()

    def _toggle_mode(self):
        if self.is_web_mode:
            self.is_web_mode = False
            self.action_mode_switch.setText("Web Play")
            self.action_mode_switch.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_ComputerIcon))
            self._setup_network_nav()
            self.signals.log.emit("info", "Switched to Network Play Mode.")
        else:
            self.is_web_mode = True
            self.action_mode_switch.setText("Network Play")
            self.action_mode_switch.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_DriveNetIcon))
            self._setup_web_nav()
            self.signals.log.emit("info", "Switched to Web Play Mode.")

    def _setup_network_nav(self):
        self.nav.clear()
        style = self.style()
        self._add_nav_item("Network Info", style.standardIcon(QtWidgets.QStyle.SP_ComputerIcon), self.info_page)
        self._add_nav_item("LAN Devices", style.standardIcon(QtWidgets.QStyle.SP_DriveNetIcon), self.devices_page)
        self._add_nav_item("Port Scanner", style.standardIcon(QtWidgets.QStyle.SP_FileDialogDetailedView), self.ports_page)
        self._add_nav_item("Traceroute", style.standardIcon(QtWidgets.QStyle.SP_ArrowRight), self.traceroute_page) 
        
        self._add_nav_item("Packet Sniffer", style.standardIcon(QtWidgets.QStyle.SP_FileDialogListView), self.traffic_page)
        self._add_nav_item("PCAP Analyzer", style.standardIcon(QtWidgets.QStyle.SP_FileIcon), self.pcap_page)
        self._add_nav_item("Network Stats", style.standardIcon(QtWidgets.QStyle.SP_ArrowUp), self.stats_page)
        self._add_nav_item("Speed Test", style.standardIcon(QtWidgets.QStyle.SP_MediaSeekForward), self.speed_page)
        self._add_nav_item("Wi-Fi Scanner", style.standardIcon(QtWidgets.QStyle.SP_FileDialogInfoView), self.wifi_page)
        self.nav.setCurrentRow(0)

    def _setup_web_nav(self):
        self.nav.clear()
        style = self.style()
        self._add_nav_item("DNS Lookup", style.standardIcon(QtWidgets.QStyle.SP_DialogHelpButton), self.dns_page)
        self._add_nav_item("Firewall Detection", style.standardIcon(QtWidgets.QStyle.SP_MessageBoxWarning), self.firewall_page)
        self._add_nav_item("SSL Inspector", style.standardIcon(QtWidgets.QStyle.SP_MessageBoxInformation), self.ssl_page)
        self._add_nav_item("WHOIS Lookup", style.standardIcon(QtWidgets.QStyle.SP_FileDialogDetailedView), self.whois_page)
        self._add_nav_item("Subdomain Scanner", style.standardIcon(QtWidgets.QStyle.SP_BrowserReload), self.subdomain_page)
        self.nav.setCurrentRow(0)

    def _add_nav_item(self, text, icon, page_widget):
        item = QtWidgets.QListWidgetItem(icon, text)
        item.setData(QtCore.Qt.UserRole, page_widget)
        self.nav.addItem(item)

    def _on_nav_click(self, row):
        if row < 0: return
        item = self.nav.item(row)
        widget = item.data(QtCore.Qt.UserRole)
        if widget: self.stack.setCurrentWidget(widget)

    def _load_initial_data(self):
        self.signals.log.emit('info', "Fetching network interfaces...")
        try:
            ifaces = get_interfaces() or ["eth0"]
            default_iface = ifaces[0]
            self.devices_page.iface_combo.clear(); self.devices_page.iface_combo.addItems(ifaces)
            self.traffic_page.iface_combo.clear(); self.traffic_page.iface_combo.addItems(ifaces)
            self.traffic_page.iface_combo.setCurrentText(default_iface)
            
            local_ip = get_local_ip()
            gateway = get_default_gateway()
            dns = get_dns_servers()
            mac_addr = get_mac_address(default_iface)
            info = {'ip': local_ip, 'gateway': gateway, 'public_ip': "Loading...", 'status': 'Connected' if local_ip != '127.0.0.1' else 'Offline', 'subnet': '255.255.255.0', 'mac': mac_addr, 'hostname': 'Localhost', 'dns1': dns[0], 'dns2': dns[1] if len(dns)>1 else "N/A"}
            self.info_page.update_info(info); self.info_page.set_system_info(default_iface) 
            self.ip_worker = PublicIpWorker(); self.ip_worker.ip_found.connect(self._on_public_ip_found); self.ip_worker.start()
            router_model = "Unknown"; self.speed_page.set_router_info(gateway, router_model)
            self.stats_worker = NetworkStatsWorker(default_iface); self.stats_worker.stats_update.connect(self.stats_page.update_stats); self.stats_worker.start()
        except Exception as e: self.signals.log.emit('error', f"Init Error: {e}")

    def _on_public_ip_found(self, ip):
        self.info_page.card_public_ip.set_value(ip); self.info_page.lbl_public_ip.setText(ip)

    def _connect_workers(self):
        self.signals.start_arp_scan.connect(self._handle_arp_start)
        self.signals.stop_arp_scan.connect(self._handle_arp_stop)
        self.signals.start_capture.connect(self._handle_capture_start)
        self.signals.stop_capture.connect(self._handle_capture_stop)
        self.signals.start_port_scan.connect(self._handle_port_start)
        self.signals.stop_port_scan.connect(self._handle_port_stop)
        self.signals.start_speed_test.connect(self._handle_speed_start)
        self.signals.start_wifi_scan.connect(self._handle_wifi_start)
        self.log_dock.visibilityChanged.connect(self._on_log_visibility_changed)
        self.signals.log.connect(self._append_log)

    # --- HANDLERS ---
    def _handle_trace_start(self, target):
        if self.traceroute_worker and self.traceroute_worker.isRunning(): return
        self.traceroute_worker = TracerouteWorker(target)
        self.traceroute_worker.new_hop.connect(self.traceroute_page.add_hop)
        self.traceroute_worker.finished.connect(self.traceroute_page.finish_trace)
        self.traceroute_worker.error_occurred.connect(lambda e: self.signals.log.emit('error', e))
        self.traceroute_worker.start()

   
        
    def _handle_ssl_start(self, domain):
        if self.ssl_worker and self.ssl_worker.isRunning(): return
        self.ssl_worker = SSLWorker(domain)
        self.ssl_worker.result_ready.connect(self.ssl_page.show_result)
        self.ssl_worker.error_occurred.connect(self.ssl_page.show_error)
        self.ssl_worker.start()

    def _handle_whois_start(self, domain):
        if self.whois_worker and self.whois_worker.isRunning(): return
        self.whois_worker = WhoisWorker(domain)
        self.whois_worker.result_ready.connect(self.whois_page.show_result)
        self.whois_worker.error_occurred.connect(self.whois_page.show_error)
        self.whois_worker.start()

    def _handle_subdomain_start(self, domain):
        if self.subdomain_worker and self.subdomain_worker.isRunning(): return
        self.subdomain_worker = SubdomainWorker(domain)
        self.subdomain_worker.found_subdomain.connect(self.subdomain_page.add_sub)
        self.subdomain_worker.finished.connect(self.subdomain_page.finish)
        self.subdomain_worker.start()

    def _handle_firewall_start(self, t):
        if self.firewall_worker and self.firewall_worker.isRunning(): return
        self.firewall_worker = FirewallScanWorker(t)
        self.firewall_worker.log.connect(self.firewall_page.append_log)
        self.firewall_worker.result.connect(self.firewall_page.show_result)
        self.firewall_worker.start()
        
    def _handle_dns_start(self, d, t):
        if self.dns_worker and self.dns_worker.isRunning(): return
        self.dns_worker = DNSLookupWorker(d, t)
        self.dns_worker.result_ready.connect(self.dns_page.show_results)
        self.dns_worker.error_occurred.connect(self.dns_page.show_error)
        self.dns_worker.start()

    def _handle_arp_start(self, iface, ip_range, use_nmap):
        if self.arp_worker and self.arp_worker.isRunning(): return
        self.arp_worker = ArpScanWorker(iface, ip_range, use_nmap)
        self.arp_worker.device_found.connect(self.devices_page.add_device)
        self.arp_worker.scan_finished.connect(self.devices_page.scan_finished)
        self.arp_worker.start()

    def _handle_arp_stop(self):
        if self.arp_worker: self.arp_worker.stop()

    def _handle_capture_start(self, iface, bpf):
        if self.capture_worker and self.capture_worker.isRunning(): return
        self.capture_worker = CaptureWorker(iface, bpf)
        self.capture_worker.packet_captured.connect(self.traffic_page.add_packet_row)
        self.capture_worker.capture_finished.connect(self.traffic_page.stop_capture_finished)
        self.capture_worker.start()
    
    def _handle_capture_stop(self):
        if self.capture_worker: self.capture_worker.stop()

    def _handle_port_start(self, target, ports_str):
        if self.port_worker and self.port_worker.isRunning(): return
        try:
            pl = []
            if not ports_str.strip(): pl = list(range(1, 1025))
            else:
                for p in ports_str.split(','):
                    if '-' in p: s,e=map(int,p.split('-')); pl.extend(range(s,e+1))
                    elif p.strip().isdigit(): pl.append(int(p))
        except: return
        self.port_worker = PortScanWorker(target, pl)
        self.port_worker.result_ready.connect(self.ports_page.add_result)
        self.port_worker.scan_finished.connect(self.ports_page.scan_finished)
        self.port_worker.start()
        
    def _handle_port_stop(self):
        if self.port_worker: self.port_worker.stop()
            
    def _handle_speed_start(self):
        if self.speed_worker and self.speed_worker.isRunning(): return
        self.speed_worker = SpeedTestWorker()
        self.speed_worker.progress_update.connect(self.speed_page.update_progress)
        self.speed_worker.finished.connect(self.speed_page.test_finished)
        self.speed_worker.start()

    def _handle_wifi_start(self):
        if self.wifi_worker and self.wifi_worker.isRunning(): return
        self.wifi_worker = WifiScanWorker()
        self.wifi_worker.network_found.connect(self.wifi_page.add_network)
        self.wifi_worker.scan_finished.connect(self.wifi_page.scan_finished)
        self.wifi_worker.error_occurred.connect(self.wifi_page.on_scan_error)
        self.wifi_worker.start()

    def _on_log_visibility_changed(self, visible):
        self.action_open_console.setEnabled(not visible)

    def _setup_global_timer(self):
        self.timer = QTimer(self); self.timer.setInterval(1000); self.timer.timeout.connect(self._update_live_widgets); self.timer.start()

    def _update_live_widgets(self):
        uptime_s = int(time.time() - self.start_time)
        self.status_uptime.setText(f"Uptime: {uptime_s}s")
        self.info_page.update_uptime_counter()
        if self.capture_worker and self.capture_worker.isRunning(): self.status_packets.setText(f"Packets: {self.capture_worker._packet_count}")

    def _append_log(self, level: str, text: str):
        ts = time.strftime('%H:%M:%S')
        color = {'info':'#00BFFF', 'success':'#00FF00', 'warn':'#FFA500', 'error':'#FF4500', 'debug':'#888888'}.get(level, '#e6f7ff')
        self.log_widget.append(f'<span style="color: {color};">[{ts}][{level.upper()}] {text}</span>')
        if level != 'debug': self.status_bar.showMessage(text, 4000)

    def closeEvent(self, event):
        # Stop all workers
        for w in [self.arp_worker, self.capture_worker, self.port_worker, self.ip_worker, self.stats_worker, self.speed_worker, self.wifi_worker, self.firewall_worker, self.dns_worker, self.traceroute_worker, self.subdomain_worker, self.ssl_worker, self.whois_worker]:
            if w: w.terminate()
        event.accept()
