"""
app/workers/ip_worker.py

A simple QThread worker to fetch the Public IP address asynchronously.
"""

from PyQt5.QtCore import QThread, pyqtSignal
from app.utils.network import get_public_ip

class PublicIpWorker(QThread):
    ip_found = pyqtSignal(str)

    def run(self):
        # This runs in a background thread
        ip = get_public_ip()
        self.ip_found.emit(ip)
