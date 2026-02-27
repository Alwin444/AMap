"""
app/workers/whois_worker.py

A QThread worker that runs the system 'whois' command.
"""

from PyQt5.QtCore import QThread, pyqtSignal
import subprocess
import logging
import shutil

logger = logging.getLogger(__name__)

class WhoisWorker(QThread):
    result_ready = pyqtSignal(str)
    error_occurred = pyqtSignal(str)

    def __init__(self, domain):
        super().__init__()
        self.domain = domain

    def run(self):
        logger.info(f"Running WHOIS for {self.domain}")
        
        if not shutil.which("whois"):
            self.error_occurred.emit("Error: 'whois' command not found. Install it: sudo apt install whois")
            return

        try:
            # Run system whois
            process = subprocess.Popen(
                ["whois", self.domain], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True
            )
            stdout, stderr = process.communicate()

            if process.returncode != 0:
                self.error_occurred.emit(f"Whois Failed: {stderr.strip()}")
            else:
                self.result_ready.emit(stdout)

        except Exception as e:
            logger.error(f"Whois Error: {e}")
            self.error_occurred.emit(str(e))
