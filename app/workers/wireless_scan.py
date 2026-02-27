"""
app/workers/wireless_scan.py

A QThread worker that scans for available Wi-Fi networks using 'nmcli'.
FIXED: Explicitly checks if a Wi-Fi adapter is present before scanning to ensure alerts trigger.
"""

from PyQt5.QtCore import QThread, pyqtSignal
import subprocess
import logging
import shutil

# Configure logging
logger = logging.getLogger(__name__)

class WifiScanWorker(QThread):
    """
    Runs 'nmcli device wifi list' to find surrounding networks.
    Emits 'network_found' for each unique network.
    """
    network_found = pyqtSignal(dict)
    scan_finished = pyqtSignal()
    error_occurred = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.is_running = True

    def run(self):
        logger.info("Starting Wi-Fi scan...")
        
        # 1. Check if nmcli is installed
        if not shutil.which("nmcli"):
            self.error_occurred.emit("Error: 'nmcli' not found. Is NetworkManager installed?")
            self.scan_finished.emit()
            return

        # 2. Explicitly check for Wi-Fi adapter presence
        # nmcli often returns exit code 0 even if no adapter exists, so we must check manually.
        if not self._check_for_adapter():
            self.error_occurred.emit("No Wi-Fi adapter detected.\n\nIf using a Virtual Machine, ensure you have connected a USB Wi-Fi adapter and enabled USB Passthrough.")
            self.scan_finished.emit()
            return

        try:
            # 3. Run Scan
            # -t : Terse mode (colon separated)
            # -f : Fields
            cmd = ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,CHAN,FREQ,SECURITY", "device", "wifi", "list"]
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()

            if process.returncode != 0:
                self.error_occurred.emit(f"Scan failed: {stderr.strip()}")
                self.scan_finished.emit()
                return

            # 4. Parse Output
            lines = stdout.strip().split('\n')
            for line in lines:
                if not self.is_running: break
                if not line: continue

                # Handle escaped colons in SSID/BSSID
                safe_line = line.replace(r'\:', '__COLON__')
                parts = safe_line.split(':')
                
                if len(parts) >= 6:
                    ssid = parts[0].replace('__COLON__', ':')
                    bssid = parts[1].replace('__COLON__', ':')
                    signal = parts[2]
                    channel = parts[3]
                    freq = parts[4]
                    security = parts[5]
                    
                    if not ssid: ssid = "<Hidden Network>"
                    
                    net_info = {
                        'ssid': ssid,
                        'bssid': bssid,
                        'signal': int(signal) if signal.isdigit() else 0,
                        'channel': channel,
                        'freq': freq,
                        'enc': security
                    }
                    
                    self.network_found.emit(net_info)

        except Exception as e:
            logger.error(f"Wi-Fi Scan Exception: {e}")
            self.error_occurred.emit(str(e))
        
        self.scan_finished.emit()

    def _check_for_adapter(self):
        """
        Checks if NetworkManager sees any device of type 'wifi'.
        Returns True if found, False otherwise.
        """
        try:
            # List all device types: nmcli -t -f TYPE device
            # Output example:
            # ethernet
            # wifi
            # loopback
            cmd = ["nmcli", "-t", "-f", "TYPE", "device"]
            output = subprocess.check_output(cmd, text=True)
            
            if "wifi" in output.splitlines():
                return True
        except Exception as e:
            logger.error(f"Adapter check failed: {e}")
            
        return False

    def stop(self):
        self.is_running = False
        self.wait()
