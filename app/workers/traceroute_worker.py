"""
app/workers/traceroute_worker.py
Runs a traceroute to map the path to a target.
"""
from PyQt5.QtCore import QThread, pyqtSignal
import subprocess
import shutil
import re

class TracerouteWorker(QThread):
    new_hop = pyqtSignal(int, str, str) # Hop No, IP, Time
    finished = pyqtSignal()
    error_occurred = pyqtSignal(str)

    def __init__(self, target):
        super().__init__()
        self.target = target
        self.is_running = True

    def run(self):
        # Check for tool (traceroute or tracert)
        cmd = "tracert" if shutil.which("tracert") else "traceroute"
        
        # -n: Do not resolve hostnames (faster)
        # -m 20: Max 20 hops
        command = [cmd, "-n", "-m", "20", self.target]
        
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            
            # Regex for Linux traceroute: " 1  192.168.1.1  1.05 ms"
            # Regex for Windows tracert:  "  1    <1 ms    <1 ms     192.168.1.1"
            
            for line in process.stdout:
                if not self.is_running:
                    process.terminate()
                    break
                
                line = line.strip()
                if not line: continue

                # Parse Hop Number (starts with digit)
                if line[0].isdigit():
                    parts = line.split()
                    try:
                        hop_num = int(parts[0])
                        # Basic parsing strategy: find the IP
                        ip = "*"
                        rtt = "*"
                        
                        # Search for IP pattern
                        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                        if ip_match:
                            ip = ip_match.group(1)
                        
                        # Search for first latency (ms)
                        ms_match = re.search(r'(\d+\.?\d*) ms', line)
                        if ms_match:
                            rtt = ms_match.group(0)
                            
                        self.new_hop.emit(hop_num, ip, rtt)
                    except:
                        pass

            self.finished.emit()
        except Exception as e:
            self.error_occurred.emit(str(e))

    def stop(self):
        self.is_running = False
        self.wait()
