"""
app/pages/speed_test_page.py

The UI for Speed Test and Router Admin.

"""

from PyQt5 import QtWidgets, QtCore, QtGui
from app.pages.base_page import BasePage, SummaryCard
import webbrowser

class SpeedTestPage(BasePage):
    def __init__(self, signals: QtCore.pyqtSignal):
        super().__init__("Speed Test & Router Admin")
        self.signals = signals
        
        # Layout Settings
        self.get_layout().setContentsMargins(20, 20, 20, 20)
        self.get_layout().setSpacing(25)
        
        # --- 1. Speed Test Controls ---
        ctrl_layout = QtWidgets.QHBoxLayout()
        
        self.run_btn = QtWidgets.QPushButton("START SPEED TEST")
        self.run_btn.setMinimumHeight(50) # Size Up
        self.run_btn.setMinimumWidth(200)
        self.run_btn.setStyleSheet("""
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
        
        self.status_label = QtWidgets.QLabel("Ready to test.")
        self.status_label.setStyleSheet("font-size: 11pt; color: #ccc; margin-left: 15px;")
        
        ctrl_layout.addWidget(self.run_btn)
        ctrl_layout.addWidget(self.status_label)
        ctrl_layout.addStretch()
        self.get_layout().addLayout(ctrl_layout)
        
        # --- 2. Speed Test Results (Cards) ---
        card_layout = QtWidgets.QHBoxLayout()
        card_layout.setSpacing(20)
        
        self.card_ping = SummaryCard("Ping", "--- ms")
        self.card_down = SummaryCard("Download", "--- Mbps")
        self.card_up = SummaryCard("Upload", "--- Mbps")
        
        for card in [self.card_ping, self.card_down, self.card_up]:
            card.setMinimumHeight(110) # Size Up
            card_layout.addWidget(card)
            
        self.get_layout().addLayout(card_layout)

        # --- 3. Progress Bars ---
        
        progress_group = QtWidgets.QGroupBox("Test Progress")
        progress_group.setStyleSheet("QGroupBox { font-weight: bold; font-size: 11pt; border: none; }")
        progress_layout = QtWidgets.QFormLayout()
        progress_layout.setSpacing(10)
        
        self.down_progress = QtWidgets.QProgressBar()
        self.down_progress.setRange(0, 100); self.down_progress.setValue(0)
        self.down_progress.setFixedHeight(25)
        
        self.up_progress = QtWidgets.QProgressBar()
        self.up_progress.setRange(0, 100); self.up_progress.setValue(0)
        self.up_progress.setFixedHeight(25)
        
        lbl_down = QtWidgets.QLabel("Download:"); lbl_down.setStyleSheet("font-size: 10pt;")
        lbl_up = QtWidgets.QLabel("Upload:"); lbl_up.setStyleSheet("font-size: 10pt;")
        
        progress_layout.addRow(lbl_down, self.down_progress)
        progress_layout.addRow(lbl_up, self.up_progress)
        progress_group.setLayout(progress_layout)
        self.get_layout().addWidget(progress_group)
        
        # --- SEPARATOR ---
        line = QtWidgets.QFrame()
        line.setFrameShape(QtWidgets.QFrame.HLine)
        line.setFrameShadow(QtWidgets.QFrame.Sunken)
        line.setStyleSheet("background-color: rgba(255,255,255,0.1);")
        self.get_layout().addWidget(line)

        # --- 4. Router Admin Section ---
        router_group = QtWidgets.QGroupBox("Router Configuration")
        router_group.setStyleSheet("QGroupBox { font-weight: bold; font-size: 11pt; margin-top: 10px; }")
        router_layout = QtWidgets.QHBoxLayout()
        router_layout.setSpacing(20)
        router_layout.setContentsMargins(15, 25, 15, 15)
        
        self.card_gw = SummaryCard("Gateway IP", "N/A")
        self.card_model = SummaryCard("Router Model", "Unknown")
        self.card_gw.setMinimumHeight(90)
        self.card_model.setMinimumHeight(90)
        
        self.open_admin_btn = QtWidgets.QPushButton("Open Router Admin")
        self.open_admin_btn.setMinimumHeight(90) 
        self.open_admin_btn.setStyleSheet("""
            QPushButton { 
                font-size: 11pt; 
                font-weight: bold; 
                border: 1px solid #00ff99; 
                color: #00ff99; 
                background: rgba(0,255,153,0.05); 
                border-radius: 8px; 
            }
            QPushButton:hover { background: rgba(0,255,153,0.15); }
        """)
        
        router_layout.addWidget(self.card_gw, 1)
        router_layout.addWidget(self.card_model, 1)
        router_layout.addWidget(self.open_admin_btn, 1)
        
        router_group.setLayout(router_layout)
        self.get_layout().addWidget(router_group)
        
        self.get_layout().addStretch()
        
        # --- Connections ---
        self.run_btn.clicked.connect(self._run)
        self.open_admin_btn.clicked.connect(self._open_gateway)

    def _run(self):
        self.signals.log.emit('info', "Starting speed test...")
        self.run_btn.setEnabled(False)
        self.status_label.setText("Testing... (Please wait)")
        self.signals.start_speed_test.emit()

    def update_progress(self, test_type: str, value: float, current_speed: float = 0):
        """Public slot for worker to update progress bars."""
        if test_type == 'ping':
            self.card_ping.set_value(f"{value:.2f} ms")
        elif test_type == 'download':
            self.down_progress.setValue(int(value))
            self.card_down.set_value(f"{current_speed:.2f} Mbps")
        elif test_type == 'upload':
            self.up_progress.setValue(int(value))
            self.card_up.set_value(f"{current_speed:.2f} Mbps")
            
    def test_finished(self, results: dict):
        """Public slot for worker to call when done."""
        self.run_btn.setEnabled(True)
        
        if not results:
            self.status_label.setText("Test Cancelled or Failed.")
            return

        self.status_label.setText("Test finished.")
        self.card_ping.set_value(f"{results.get('ping', 0):.2f} ms")
        self.card_down.set_value(f"{results.get('download', 0):.2f} Mbps")
        self.card_up.set_value(f"{results.get('upload', 0):.2f} Mbps")
        self.down_progress.setValue(100)
        self.up_progress.setValue(100)
        self.signals.log.emit('success', "Speed test complete.")

    def set_router_info(self, ip: str, model: str):
        """Updates the router admin card."""
        self.card_gw.set_value(ip)
        self.card_model.set_value(model)

    def _open_gateway(self):
        gateway_ip = self.card_gw.value_label.text()
        if gateway_ip == 'N/A':
            self.signals.log.emit('error', "Gateway IP not found.")
            return
        self.signals.log.emit('info', f"Opening http://{gateway_ip} in browser...")
        try:
            webbrowser.open(f'http://{gateway_ip}')
        except Exception as e:
            self.signals.log.emit('error', f"Failed to open browser: {e}")
