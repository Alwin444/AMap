"""
app/pages/info_dashboard.py

The UI for the Network Information Dashboard.
Refined layout: Taller cards, equal-width panels, better spacing.
"""

from PyQt5 import QtWidgets, QtCore, QtGui
from app.pages.base_page import BasePage, SummaryCard
import time
import psutil

class InfoDashboardPage(BasePage):
    def __init__(self, signals: QtCore.pyqtSignal):
        super().__init__('Network Information Dashboard')
        self.signals = signals
        
        # Main Layout: Vertical with spacing
        self.get_layout().setContentsMargins(20, 20, 20, 20)
        self.get_layout().setSpacing(20)

        # --- 1. Top Summary Cards ---
        card_layout = QtWidgets.QHBoxLayout()
        card_layout.setSpacing(15)
        
        self.card_ip = SummaryCard('Local IP', 'N/A')
        self.card_gw = SummaryCard('Gateway', 'N/A')
        self.card_public_ip = SummaryCard('Public IP', 'N/A')
        self.card_status = SummaryCard('Status', 'N/A')
        
        # Size Up: Make cards taller and uniform
        for card in [self.card_ip, self.card_gw, self.card_public_ip, self.card_status]:
            card.setMinimumHeight(100)
            card_layout.addWidget(card)
            
        self.get_layout().addLayout(card_layout)

        # --- 2. Detailed Info Panels (Side-by-Side) ---
        panels_layout = QtWidgets.QHBoxLayout()
        panels_layout.setSpacing(15)
        
        # Left Panel: Interface Details
        iface_group = QtWidgets.QGroupBox("Interface Details")
        iface_group.setStyleSheet("QGroupBox { font-weight: bold; font-size: 11pt; }")
        info_layout = QtWidgets.QFormLayout()
        info_layout.setContentsMargins(15, 20, 15, 15)
        info_layout.setSpacing(10)
        
        self.lbl_ip = QtWidgets.QLabel("N/A")
        self.lbl_subnet = QtWidgets.QLabel("N/A")
        self.lbl_gateway = QtWidgets.QLabel("N/A")
        self.lbl_mac = QtWidgets.QLabel("N/A")
        
        # Style labels for better visibility
        for lbl in [self.lbl_ip, self.lbl_subnet, self.lbl_gateway, self.lbl_mac]:
            lbl.setStyleSheet("font-size: 10pt; color: #00ff99;")

        info_layout.addRow("IP Address:", self.lbl_ip)
        info_layout.addRow("Subnet Mask:", self.lbl_subnet)
        info_layout.addRow("Gateway:", self.lbl_gateway)
        info_layout.addRow("MAC Address:", self.lbl_mac)
        iface_group.setLayout(info_layout)
        
        # Right Panel: System & DNS
        other_group = QtWidgets.QGroupBox("System & DNS")
        other_group.setStyleSheet("QGroupBox { font-weight: bold; font-size: 11pt; }")
        other_layout = QtWidgets.QFormLayout()
        other_layout.setContentsMargins(15, 20, 15, 15)
        other_layout.setSpacing(10)

        self.lbl_hostname = QtWidgets.QLabel("N/A")
        self.lbl_dns1 = QtWidgets.QLabel("N/A")
        self.lbl_dns2 = QtWidgets.QLabel("N/A")
        self.lbl_public_ip = QtWidgets.QLabel("N/A")
        
        for lbl in [self.lbl_hostname, self.lbl_dns1, self.lbl_dns2, self.lbl_public_ip]:
            lbl.setStyleSheet("font-size: 10pt; color: #00ff99;")
        
        other_layout.addRow("Hostname:", self.lbl_hostname)
        other_layout.addRow("Primary DNS:", self.lbl_dns1)
        other_layout.addRow("Secondary DNS:", self.lbl_dns2)
        other_layout.addRow("Public IP:", self.lbl_public_ip)
        other_group.setLayout(other_layout)
        
        # Add to layout with equal stretch (1, 1)
        panels_layout.addWidget(iface_group, 1)
        panels_layout.addWidget(other_group, 1)
        
        self.get_layout().addLayout(panels_layout)

        # --- 3. System Tracker Section (Bottom) ---
        tracker_group = QtWidgets.QGroupBox("System Tracker")
        tracker_group.setStyleSheet("QGroupBox { font-weight: bold; font-size: 11pt; margin-top: 10px; }")
        tracker_layout = QtWidgets.QHBoxLayout()
        tracker_layout.setSpacing(15)
        tracker_layout.setContentsMargins(15, 20, 15, 15)
        
        self.card_iface_active = SummaryCard("Active Interface", "eth0")
        self.card_boot = SummaryCard("System Boot", "N/A")
        self.card_uptime = SummaryCard("System Uptime", "0s")
        
        for card in [self.card_iface_active, self.card_boot, self.card_uptime]:
            card.setMinimumHeight(90) # Slightly smaller than top cards
            tracker_layout.addWidget(card)
            
        tracker_group.setLayout(tracker_layout)
        self.get_layout().addWidget(tracker_group)
        
        self.get_layout().addStretch()
        
        # Initialize static boot time
        try:
            self.boot_time = psutil.boot_time()
            self.card_boot.set_value(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.boot_time)))
        except Exception:
            self.boot_time = None
            self.card_boot.set_value("Unknown")

    def update_info(self, info: dict):
        self.card_ip.set_value(info.get('ip', 'N/A'))
        self.card_gw.set_value(info.get('gateway', 'N/A'))
        self.card_public_ip.set_value(info.get('public_ip', 'N/A'))
        self.card_status.set_value(info.get('status', 'N/A'))
        
        self.lbl_ip.setText(info.get('ip', 'N/A'))
        self.lbl_subnet.setText(info.get('subnet', 'N/A'))
        self.lbl_gateway.setText(info.get('gateway', 'N/A'))
        self.lbl_mac.setText(info.get('mac', 'N/A'))
        self.lbl_hostname.setText(info.get('hostname', 'N/A'))
        self.lbl_dns1.setText(info.get('dns1', 'N/A'))
        self.lbl_dns2.setText(info.get('dns2', 'N/A'))
        self.lbl_public_ip.setText(info.get('public_ip', 'N/A'))

    def update_uptime_counter(self):
        if self.boot_time:
            uptime_s = int(time.time() - self.boot_time)
            m, s = divmod(uptime_s, 60)
            h, m = divmod(m, 60)
            d, h = divmod(h, 24)
            self.card_uptime.set_value(f"{d}d {h}h {m}m {s}s")

    def set_system_info(self, iface):
        self.card_iface_active.set_value(iface)
