"""
app/workers/subdomain_worker.py
Finds subdomains using crt.sh public API (OSINT).
"""
from PyQt5.QtCore import QThread, pyqtSignal
import requests
import json

class SubdomainWorker(QThread):
    found_subdomain = pyqtSignal(str)
    finished = pyqtSignal(int) # total found
    
    def __init__(self, domain):
        super().__init__()
        self.domain = domain

    def run(self):
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                data = r.json()
                seen = set()
                for entry in data:
                    name = entry['name_value']
                    # Handle multi-line names
                    for sub in name.split('\n'):
                        if sub not in seen and not "*" in sub:
                            self.found_subdomain.emit(sub)
                            seen.add(sub)
                self.finished.emit(len(seen))
                return
        except Exception:
            pass
        self.finished.emit(0)
