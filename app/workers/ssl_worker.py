"""
app/workers/ssl_worker.py

A QThread worker that retrieves SSL/TLS certificate details for a domain.
"""

from PyQt5.QtCore import QThread, pyqtSignal
import ssl
import socket
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class SSLWorker(QThread):
    result_ready = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self, hostname, port=443):
        super().__init__()
        self.hostname = hostname
        self.port = port

    def run(self):
        logger.info(f"Fetching SSL info for {self.hostname}:{self.port}")
        
        context = ssl.create_default_context()
        
        try:
            with socket.create_connection((self.hostname, self.port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Parse Data
                    subject = dict(x[0] for x in cert['subject'])
                    issuer = dict(x[0] for x in cert['issuer'])
                    
                    # Dates
                    date_fmt = r'%b %d %H:%M:%S %Y %Z'
                    not_before = datetime.strptime(cert['notBefore'], date_fmt)
                    not_after = datetime.strptime(cert['notAfter'], date_fmt)
                    days_left = (not_after - datetime.now()).days
                    
                    info = {
                        'domain': self.hostname,
                        'common_name': subject.get('commonName', 'Unknown'),
                        'issuer': issuer.get('organizationName', issuer.get('commonName', 'Unknown')),
                        'valid_from': not_before.strftime('%Y-%m-%d'),
                        'valid_until': not_after.strftime('%Y-%m-%d'),
                        'days_left': days_left,
                        'secure': True
                    }
                    self.result_ready.emit(info)

        except Exception as e:
            logger.error(f"SSL Check Failed: {e}")
            self.error_occurred.emit(str(e))
