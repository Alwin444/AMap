"""
app/workers/stats_worker.py

A QThread worker that monitors real-time network bandwidth usage
and active connections (Top Talkers).
"""

from PyQt5.QtCore import QThread, pyqtSignal
import psutil
import time
import logging
from collections import Counter

# Configure logging
logger = logging.getLogger(__name__)

class NetworkStatsWorker(QThread):
    """
    Monitors network I/O stats and active connections.
    Emits 'stats_update' signal.
    """
    # Signal emits: (down_kbps, up_kbps, total_down_mb, total_up_mb, talkers_dict)
    stats_update = pyqtSignal(float, float, float, float, dict)
    
    def __init__(self, interface="eth0"):
        super().__init__()
        self.interface = interface
        self.is_running = True

    def run(self):
        logger.info(f"Starting stats monitoring on {self.interface}")
        
        last_io = self._get_io_counters()
        last_time = time.time()
        
        while self.is_running:
            time.sleep(1.0) # Update every second
            
            current_io = self._get_io_counters()
            current_time = time.time()
            
            # 1. Calculate Speed
            bytes_recv = current_io.bytes_recv - last_io.bytes_recv
            bytes_sent = current_io.bytes_sent - last_io.bytes_sent
            time_diff = current_time - last_time
            if time_diff == 0: time_diff = 1.0
            
            down_kbps = (bytes_recv * 8) / 1024 / time_diff
            up_kbps = (bytes_sent * 8) / 1024 / time_diff
            
            total_down_mb = current_io.bytes_recv / (1024 * 1024)
            total_up_mb = current_io.bytes_sent / (1024 * 1024)
            
            # 2. Get Top Talkers (Active Connections)
            # Note: psutil.net_connections requires root for some PIDs, 
            # but works for general network analysis.
            talkers = {}
            try:
                connections = psutil.net_connections(kind='inet')
                remote_ips = []
                for c in connections:
                    if c.status == 'ESTABLISHED' and c.raddr:
                        remote_ips.append(c.raddr.ip)
                
                # Count occurrences: { '1.1.1.1': 5, '192.168.1.5': 2 }
                # This represents "Active Connections", a good proxy for "Talkers"
                talkers = dict(Counter(remote_ips).most_common(10))
            except Exception:
                pass # Permission denied or other error

            self.stats_update.emit(down_kbps, up_kbps, total_down_mb, total_up_mb, talkers)
            
            last_io = current_io
            last_time = current_time

    def _get_io_counters(self):
        try:
            counters = psutil.net_io_counters(pernic=True)
            if self.interface in counters:
                return counters[self.interface]
            return psutil.net_io_counters()
        except:
            return psutil.net_io_counters()

    def stop(self):
        self.is_running = False
        self.wait()
