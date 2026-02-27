"""
app/pages/wifi_scanner_page.py

The UI for the Surrounding Wi-Fi Scanner.
Features:
- Lists SSID, BSSID, Signal, Channel, Security.
- Updates 'Best Signal' card dynamically.
- Professional Layout.
- Popup Alert for missing adapter.
"""

from PyQt5 import QtWidgets, QtCore, QtGui
from app.pages.base_page import BasePage, SummaryCard

class WifiScannerPage(BasePage):
    def __init__(self, signals: QtCore.pyqtSignal):
        super().__init__("Surrounding Wi-Fi Scanner")
        self.signals = signals
        self.best_signal_val = -100

        # Layout Settings
        self.get_layout().setContentsMargins(20, 20, 20, 20)
        self.get_layout().setSpacing(20)

        # --- 1. Top Controls & Cards ---
        top_row = QtWidgets.QHBoxLayout()
        top_row.setSpacing(20)
        
        # Left: Scan Button
        self.scan_btn = QtWidgets.QPushButton("Scan for Networks")
        self.scan_btn.setMinimumHeight(50) # Size Up
        self.scan_btn.setMinimumWidth(200)
        self.scan_btn.setStyleSheet("""
            QPushButton { 
                background-color: #00BFFF; 
                color: white; 
                font-size: 12pt; 
                font-weight: bold; 
                border-radius: 8px; 
            }
            QPushButton:hover { background-color: #00AADD; }
            QPushButton:disabled { background-color: #555; }
        """)
        
        top_row.addWidget(self.scan_btn)
        top_row.addStretch()
        
        # Right: Summary Cards
        self.card_found = SummaryCard("Networks Found", "0")
        self.card_best = SummaryCard("Best Signal", "---")
        
        for card in [self.card_found, self.card_best]:
            card.setMinimumHeight(100) # Size Up
            card.setMinimumWidth(160)
            top_row.addWidget(card)
            
        self.get_layout().addLayout(top_row)
        
        # --- 2. Results Table ---
        self.table = QtWidgets.QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["SSID", "BSSID", "Signal (%)", "Channel", "Frequency", "Encryption"])
        
        # Table Styling
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QtWidgets.QHeaderView.Interactive) 
        self.table.setColumnWidth(0, 200)
        
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        
        # Custom Table Style
        self.table.setStyleSheet("""
            QTableWidget { 
                border: 1px solid #3d4a59; 
                background-color: rgba(10, 30, 45, 0.6); 
                color: #e6f7ff;
                gridline-color: rgba(0, 255, 153, 0.1);
                font-size: 10pt;
            }
            QTableWidget::item { padding: 5px; }
            QTableWidget::item:selected {
                background-color: rgba(0, 255, 153, 0.2);
                color: #ffffff;
            }
            QHeaderView::section {
                background-color: rgba(15, 42, 58, 1);
                color: #00ff99;
                border: none;
                padding: 6px;
                font-weight: bold;
                font-size: 10pt;
            }
        """)
        
        self.get_layout().addWidget(self.table)
        
        # --- 3. Footer Warning ---
        self.warning_label = QtWidgets.QLabel("Note: Requires a compatible Wi-Fi adapter (e.g., wlan0). Internal VM adapters usually appear as Ethernet.")
        self.warning_label.setStyleSheet("color: #888; font-style: italic; margin-top: 5px;")
        self.get_layout().addWidget(self.warning_label)
        
        # --- Connections ---
        self.scan_btn.clicked.connect(self._start_scan)

    def _start_scan(self):
        self.scan_btn.setEnabled(False)
        self.scan_btn.setText("Scanning...")
        
        # Disable sorting while populating to prevent jumping
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        
        # Reset stats
        self.best_signal_val = -100
        self.card_found.set_value("0")
        self.card_best.set_value("---")
        
        self.signals.log.emit('info', "Starting Wi-Fi scan (nmcli)...")
        self.signals.start_wifi_scan.emit()

    def add_network(self, net: dict):
        """Public slot for worker to add a network."""
        r = self.table.rowCount()
        self.table.insertRow(r)
        
        # SSID
        self.table.setItem(r, 0, QtWidgets.QTableWidgetItem(net['ssid']))
        # BSSID
        self.table.setItem(r, 1, QtWidgets.QTableWidgetItem(net['bssid']))
        
        # Signal (Color coded)
        sig_val = net['signal']
        sig_item = QtWidgets.QTableWidgetItem(str(sig_val))
        
        if sig_val > 70:
            sig_item.setForeground(QtGui.QColor("#00FF00")) # Good (Green)
        elif sig_val > 40:
            sig_item.setForeground(QtGui.QColor("#FFA500")) # Fair (Orange)
        else:
            sig_item.setForeground(QtGui.QColor("#FF4500")) # Poor (Red)
            
        self.table.setItem(r, 2, sig_item)
        
        self.table.setItem(r, 3, QtWidgets.QTableWidgetItem(str(net['channel'])))
        self.table.setItem(r, 4, QtWidgets.QTableWidgetItem(str(net['freq'])))
        self.table.setItem(r, 5, QtWidgets.QTableWidgetItem(net['enc']))
        
        # Update Summary Cards
        self.card_found.set_value(str(r + 1))
        
        if sig_val > self.best_signal_val:
            self.best_signal_val = sig_val
            self.card_best.set_value(f"{self.best_signal_val}%")

    def scan_finished(self):
        """Public slot for worker to call when finished."""
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("Scan for Networks")
        self.table.setSortingEnabled(True) # Re-enable sorting
        self.signals.log.emit('success', f"Wi-Fi scan finished. Found {self.table.rowCount()} networks.")

    def on_scan_error(self, message):
        """Displays a popup alert when scan fails (e.g., no adapter)."""
        self.scan_finished() # Reset button state
        QtWidgets.QMessageBox.warning(self, "Wi-Fi Scan Error", message)
